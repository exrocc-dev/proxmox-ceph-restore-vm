"""
단계 E-1 — BlueFS file_map 으로부터 RocksDB 디렉터리 byte 추출

목적: 단계 D 의 file_map.extents 따라 raw 의 byte 들을 별도 디렉터리에
      RocksDB 표준 layout (db/, db.slow/, db.wal/, sharding/) 으로 dump.
      이후 단계 E-2 가 이 디렉터리를 read-only 로 rocksdict open.

R8: raw .001 은 read-only 로만 open. 출력은 별도 디렉터리.
조건 (사용자 명시):
  1. fnode.size 만큼만 write (logical size) — extent allocation overhead 제거
  2. 추출된 파일 byte = raw 의 byte concat (변경 X)
  3. 추출 후 SHA-256 측정 (open 전 oracle)
"""
import sys
import hashlib
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import (
    OSD3_DIR, RAWS, PV_LV_OFFSET, SUPER_OFFSET_LV, SUPER_BLOCK_SIZE,
    decode_super, replay,
)

from _dataset_path import EXTRACTED_BASE as OUTPUT_BASE, OSD_RAW
# OSD_NAMES: pveX.001 → osd.<idx> (auto from OSD_RAW)
OSD_NAMES = {p.name: osd for osd, p in OSD_RAW.items()}


def extract_one_osd(raw_path: Path, file_map: dict, dir_map: dict, out_dir: Path):
    """file_map + dir_map 따라 byte 들을 out_dir 에 추출."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for dirname in dir_map:
        (out_dir / dirname).mkdir(parents=True, exist_ok=True)

    # ino -> (relative path within out_dir, fnode)
    ino_to_path = {}
    for dirname, files in dir_map.items():
        for fname, ino in files.items():
            ino_to_path[ino] = Path(dirname) / fname

    extracted = []
    skipped_no_link = []
    skipped_log_self = []

    with open(raw_path, "rb") as raw_f:
        for ino, fn in sorted(file_map.items()):
            if ino == 1:
                # BlueFS log 자체 — RocksDB 와 무관 (단 metadata source)
                skipped_log_self.append(ino)
                continue
            if ino not in ino_to_path:
                skipped_no_link.append(ino)
                continue

            rel_path = ino_to_path[ino]
            out_path = out_dir / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            size = fn["size"]

            with open(out_path, "wb") as out_f:
                remaining = size
                for ext in fn["extents"]:
                    if remaining <= 0:
                        break
                    raw_f.seek(PV_LV_OFFSET + ext["offset"])
                    take = min(ext["length"], remaining)
                    chunk = raw_f.read(take)
                    if len(chunk) != take:
                        raise IOError(f"short read at PV 0x{PV_LV_OFFSET + ext['offset']:x}: "
                                      f"requested {take}, got {len(chunk)}")
                    out_f.write(chunk)
                    remaining -= take
                if remaining > 0:
                    raise ValueError(f"ino {ino}: extents exhausted with {remaining} byte still needed")

            # SHA-256 of extracted file
            h = hashlib.sha256()
            with open(out_path, "rb") as f:
                while True:
                    blk = f.read(1024 * 1024)
                    if not blk:
                        break
                    h.update(blk)

            extracted.append({
                "ino": ino,
                "rel_path": str(rel_path).replace("\\", "/"),
                "size": size,
                "extent_count": len(fn["extents"]),
                "sha256": h.hexdigest(),
            })

    return {
        "extracted": extracted,
        "skipped_no_link": skipped_no_link,
        "skipped_log_self": skipped_log_self,
    }


def main():
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("단계 E-1 — BlueFS file_map 으로부터 RocksDB 디렉터리 추출")
    print(f"Output base: {OUTPUT_BASE}")
    print("=" * 80)

    summary_all = {}

    for raw_name in RAWS:
        path = OSD3_DIR / raw_name
        out_dir = OUTPUT_BASE / OSD_NAMES[raw_name]

        # 단계 D replay 다시 (결정성 입증된 도구)
        with open(path, "rb") as f:
            f.seek(PV_LV_OFFSET + SUPER_OFFSET_LV)
            block = f.read(SUPER_BLOCK_SIZE)
        super_info = decode_super(block)
        result = replay(path, super_info)

        print(f"\n{'─' * 80}")
        print(f"{raw_name} → {out_dir}")
        print(f"{'─' * 80}")

        info = extract_one_osd(path, result["file_map"], result["dir_map"], out_dir)

        # 통계
        n = len(info["extracted"])
        total_bytes = sum(e["size"] for e in info["extracted"])
        by_kind = {}
        for e in info["extracted"]:
            kind = e["rel_path"].split("/")[0] + "/" + (
                "*.sst" if e["rel_path"].endswith(".sst") else
                "*.log" if e["rel_path"].endswith(".log") else
                "MANIFEST" if "MANIFEST" in e["rel_path"] else
                "OPTIONS" if "OPTIONS" in e["rel_path"] else
                e["rel_path"].split("/")[-1])
            by_kind[kind] = by_kind.get(kind, 0) + 1

        print(f"  files extracted:     {n}")
        print(f"  total bytes written: {total_bytes:,} ({total_bytes / 1024**2:.2f} MiB)")
        print(f"  skipped (log_file):  {info['skipped_log_self']}")
        print(f"  skipped (no link):   {info['skipped_no_link']}")
        print(f"  by kind:")
        for k in sorted(by_kind):
            print(f"    {k:<30s} {by_kind[k]:>4d}")

        # 산출물 manifest 저장
        manifest = {
            "osd_name": OSD_NAMES[raw_name],
            "raw_path": str(path),
            "raw_size": path.stat().st_size,
            "super_osd_uuid": super_info["osd_uuid"],
            "super_uuid": super_info["uuid"],
            "replay_accepted": result["accepted"],
            "replay_last_seq": result["last_seq"],
            "files": info["extracted"],
            "skipped_no_link": info["skipped_no_link"],
            "skipped_log_self": info["skipped_log_self"],
        }
        manifest_path = out_dir / "_extract_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        print(f"  manifest:            {manifest_path.name}")

        summary_all[OSD_NAMES[raw_name]] = {
            "files": n,
            "total_bytes": total_bytes,
        }

    print(f"\n{'=' * 80}")
    print("E-1 SUMMARY (RocksDB 추출 완료, open 전 SHA-256 oracle 확보)")
    print('=' * 80)
    for osd, s in summary_all.items():
        print(f"  {osd}: {s['files']} files, {s['total_bytes'] / 1024**2:.2f} MiB")
    print(f"\n  → 다음: step_e2 가 이 디렉터리를 read-only rocksdict 로 open")


if __name__ == "__main__":
    main()
