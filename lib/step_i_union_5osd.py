"""
다중 OSD union image 추출 (단계 I 메인 진입점).

algorithm:
  1. 각 OSD 의 SST + WAL union state 수집 → 그 OSD 가 가진 chunks 의 onode
  2. OSD 간 chunk bn → state 합집합. 같은 bn 이 여러 OSD 에 동일 byte 로 있으면 채택,
     OSD 간 conflict 가 발생하면 majority-vote 로 본 chunk 를 선택
  3. logical offset 순서로 chunk byte 를 합쳐 가상머신 디스크 raw 이미지를 출력

호출:
  python step_i_union_5osd.py <image_id>
"""
import sys
import hashlib
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent))
from _dataset_path import EXTRACTED_BASE, OSDS, OSD_RAW
from step_f_sst_wal_union import open_readonly
from step_i_image_extract import (
    collect_sst_state, apply_wal_state, parse_chunk_key_bn, extract_chunk,
    load_image_metadata,
)


def gather_per_osd_chunks(image_id: str) -> dict:
    """각 OSD 별 chunk bn → (key, value) state 수집."""
    out = {}
    for osd in OSDS:
        db_dir = EXTRACTED_BASE / osd / "db"
        if not (db_dir / "CURRENT").exists():
            # 빈 OSD — 청크 없음으로 처리
            out[osd] = {"state": {}, "chunks": {}}
            continue
        db, cf_list = open_readonly(db_dir)
        state = collect_sst_state(db, cf_list, image_id)
        db.close()
        apply_wal_state(state, osd, image_id)

        chunks = {}
        for k, v in state.items():
            bn = parse_chunk_key_bn(k, image_id)
            if bn is not None:
                chunks[bn] = (k, v)
        out[osd] = {"state": state, "chunks": chunks}
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: step_i_union_5osd.py <image_id>", file=sys.stderr)
        return 2
    image_id = sys.argv[1]

    meta = load_image_metadata(image_id)
    if meta is None:
        print(f"  ERROR: image_id={image_id} 의 메타데이터 (size/order) 를 단계 G 결과에서 "
              f"찾지 못함. rbd_header 가 OSD raw 에 보존되어 있지 않을 수 있음.", file=sys.stderr)
        return 1

    image_size = meta["image_size"]
    order = meta["order"]
    object_size = 1 << order
    n_chunks_total = image_size // object_size
    vm_name = meta["vm_name"]

    print("=" * 100)
    print(f"단계 I — {vm_name} (id={image_id}, {image_size/1024**3:.0f} GiB, {n_chunks_total} chunks)")
    print("=" * 100)

    print("\n  1) OSD 별 chunk state 수집…")
    per_osd = gather_per_osd_chunks(image_id)
    for osd, info in per_osd.items():
        print(f"    {osd}: {len(info['chunks'])} unique bn")

    # 2) chunk bn 분포 — 각 bn 이 몇 OSD 에 있나
    print(f"\n  2) chunk bn 분포 (각 bn 이 몇 OSD 에 보유):")
    bn_to_osds = defaultdict(set)
    for osd, info in per_osd.items():
        for bn in info["chunks"]:
            bn_to_osds[bn].add(osd)
    by_count = Counter(len(s) for s in bn_to_osds.values())
    print(f"    OSD 보유 갯수 별 chunk count: {dict(by_count)}")
    print(f"    총 unique bn: {len(bn_to_osds)}")

    if not bn_to_osds:
        print(f"\n  → image_id={image_id} 의 chunk 가 어느 OSD 에서도 발견되지 않음. "
              f"잔재 후보이거나 회수 가능 범위 밖.", file=sys.stderr)
        return 1

    # 3) extract per chunk (byte 단위) + OSD 간 일치성 측정
    print(f"\n  3) chunk extract (OSD 간 일치성 측정)…")
    out_image = bytearray(image_size)
    n_consensus = 0  # >= 2 OSD 가 같은 byte
    n_conflict = 0   # OSD 간 byte 불일치 → majority vote
    n_single = 0     # 1 OSD 만 보유 (비교 불가)
    for bn, osd_set in sorted(bn_to_osds.items()):
        chunk_per_osd = {}
        for osd in osd_set:
            k, v = per_osd[osd]["chunks"][bn]
            raw_path = OSD_RAW[osd]
            chunk_bytes, _info = extract_chunk(per_osd[osd]["state"], k, v, raw_path)
            chunk_per_osd[osd] = chunk_bytes
        if len(chunk_per_osd) == 1:
            n_single += 1
            chosen = list(chunk_per_osd.values())[0]
        else:
            shas = {osd: hashlib.sha256(c).hexdigest() for osd, c in chunk_per_osd.items()}
            unique = set(shas.values())
            if len(unique) == 1:
                n_consensus += 1
                chosen = list(chunk_per_osd.values())[0]
            else:
                n_conflict += 1
                # majority vote
                cnt = Counter(shas.values())
                top_sha, _ = cnt.most_common(1)[0]
                chosen = next(c for o, c in chunk_per_osd.items() if shas[o] == top_sha)
        offset = bn * object_size
        out_image[offset:offset + len(chosen)] = chosen

    sha = hashlib.sha256(out_image).hexdigest()
    print(f"\n  4) 회수 image SHA-256 = {sha}")
    print(f"\n  OSD 간 일치성:")
    print(f"     1-OSD only chunks            : {n_single}")
    print(f"     ≥ 2-OSD consensus chunks     : {n_consensus}")
    print(f"     ≥ 2-OSD conflict chunks      : {n_conflict}")

    # save image
    out_path = EXTRACTED_BASE / "_i_results" / f"{vm_name}_union.raw"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(out_image)
    print(f"\n  saved: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
