#!/usr/bin/env python3
"""
restore_vms.py — Inactive OSD raw 이미지로부터 RBD 가상머신 디스크 회수

본 도구는 학위논문 "비활성 상태에서의 분산 객체 스토리지 데이터 회수 방안
— Proxmox-Ceph 환경을 중심으로" (석동현, 성균관대학교, 2026) 의
회수 메커니즘을 단일 진입점 CLI 로 제공한다.

활성 Ceph 클러스터의 동작이나 외부 도구의 mount 없이, OSD 디스크의 raw
이미지만으로 RBD 가상머신 디스크를 byte 단위로 회수한다.

사용법:
  python restore_vms.py --osd-dir /path/to/osd/images --output /path/to/output

  # 특정 가상머신만 회수
  python restore_vms.py --osd-dir ./osds --output ./recovered \\
                        --image-id fbabeb6914038

인자 설명:
  --osd-dir          OSD raw 이미지가 든 디렉터리. *.001, *.raw, *.img 자동 발견
  --output           회수 결과 출력 디렉터리 (자동 생성)
  --osd-glob         OSD 파일 glob 패턴 (세미콜론 구분, 기본 *.001;*.raw;*.img)
  --image-id         특정 image_id 만 회수 (반복 가능)
  --skip-bluefs      BlueStore 메타데이터 영역 복원 단계 skip (이미 추출됨)
  --skip-wal         RocksDB WAL 파싱 단계 skip (이미 추출됨)

의존성:
  - Python 3.11+
  - rocksdict (pip install rocksdict)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Windows 콘솔(cp949) 에서 한글 깨짐 방지
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

THIS_DIR = Path(__file__).resolve().parent
LIB_DIR = THIS_DIR / "lib"


def discover_osd_files(osd_dir: Path, glob_patterns: list[str]) -> list[Path]:
    candidates: set[Path] = set()
    for pat in glob_patterns:
        for p in osd_dir.glob(pat):
            if p.is_file():
                candidates.add(p)
    return sorted(candidates, key=lambda p: p.name)


def run_step(script: Path, env: dict, log_path: Path,
             extra_args: list[str] | None = None) -> int:
    """step 모듈을 subprocess 로 실행. stdout/stderr 은 log 파일로 redirect.

    화면에는 표시되지 않으며, 디버깅이 필요하면 log_path 를 직접 열어 확인한다.
    """
    extra_args = extra_args or []
    cmd = [sys.executable, "-u", str(script)] + extra_args
    with open(log_path, "ab") as logf:
        header = f"\n\n===== {script.name} {' '.join(extra_args)} =====\n"
        logf.write(header.encode("utf-8"))
        logf.flush()
        proc = subprocess.run(cmd, env=env, cwd=str(LIB_DIR),
                              stdout=logf, stderr=subprocess.STDOUT)
    return proc.returncode


def sha256_streaming(path: Path, chunk_size: int = 1 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(chunk_size), b""):
            h.update(buf)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def extract_active_images(f_data: dict) -> dict[str, str]:
    """단계 F 결과에서 활성 가상머신 image_id → vm_name 매핑 추출."""
    out: dict[str, str] = {}
    for osd_name, osd_data in f_data.items():
        if not isinstance(osd_data, dict):
            continue
        final_omap = osd_data.get("final_omap") or {}
        for key, entry in final_omap.items():
            if not key.startswith("id_"):
                continue
            image_id = key[3:]
            vm_name = entry.get("value_str", "?") if isinstance(entry, dict) else "?"
            out[image_id] = vm_name
    return out


def chunk_traces(f_data: dict, image_id: str) -> tuple[list[str], int, int]:
    """image_id 의 OSD 별 흔적 통계.

    SST 의 onode 잔존 + WAL PUT 의 합을 "흔적 chunk", WAL DEL 후 살아남은
    수를 "잔존 chunk" 로 정의한다. 분석자는 두 값을 비교하여 cleanup
    진행 정도를 가늠한다.

    Returns:
      (흔적이 발견된 OSD 목록, OSD 별 최대 흔적 chunk 수, OSD 별 최대 잔존 chunk 수)
    """
    holders = []
    max_trace = 0
    max_final = 0
    for osd_name, osd_data in f_data.items():
        if not isinstance(osd_data, dict):
            continue
        cu = (osd_data.get("chunk_union") or {}).get(image_id) or {}
        trace = cu.get("sst_count", 0) + cu.get("wal_put", 0)
        final = cu.get("final_count", 0)
        if trace > 0:
            holders.append(osd_name)
        if trace > max_trace:
            max_trace = trace
        if final > max_final:
            max_final = final
    return sorted(holders), max_trace, max_final


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inactive OSD raw → RBD VM disk recovery (Proxmox-Ceph)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--osd-dir", required=True, type=Path,
                        help="OSD raw 이미지가 든 디렉터리")
    parser.add_argument("--output", required=True, type=Path,
                        help="회수 결과 출력 디렉터리 (자동 생성)")
    parser.add_argument("--osd-glob", default="*.001;*.raw;*.img",
                        help="OSD raw 파일 glob 패턴 (세미콜론 구분; 기본 *.001;*.raw;*.img)")
    parser.add_argument("--image-id", action="append", default=None,
                        help="특정 image_id 만 회수 (반복 가능; 미지정 시 모든 활성 가상머신)")
    parser.add_argument("--skip-bluefs", action="store_true",
                        help="BlueStore 메타데이터 영역 복원 skip (이미 추출된 RocksDB 재사용)")
    parser.add_argument("--skip-wal", action="store_true",
                        help="RocksDB WAL 파싱 skip (이미 추출됨)")
    args = parser.parse_args()

    if not args.osd_dir.exists() or not args.osd_dir.is_dir():
        print(f"ERROR: --osd-dir 이 디렉터리가 아니다: {args.osd_dir}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)

    glob_patterns = [p.strip() for p in args.osd_glob.split(";") if p.strip()]
    osd_files = discover_osd_files(args.osd_dir, glob_patterns)
    if not osd_files:
        print(f"ERROR: OSD raw 이미지를 발견하지 못함. dir={args.osd_dir}, "
              f"glob='{args.osd_glob}'", file=sys.stderr)
        return 2

    print()
    print(f"  OSD raw 디렉터리: {args.osd_dir}")
    print(f"  출력 디렉터리   : {args.output}")
    print(f"  발견된 OSD raw  : {len(osd_files)} 개")
    for p in osd_files:
        size_mib = p.stat().st_size / 1024 / 1024
        print(f"    - {p.name}  ({size_mib:,.0f} MiB)")
    print()

    # subprocess 호출 환경 설정
    env = os.environ.copy()
    env["OSD_RAW_DIR"] = str(args.osd_dir.resolve())
    env["OUTPUT_DIR"] = str(args.output.resolve())
    env["OSD_GLOB"] = args.osd_glob
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

    log_path = args.output / "restore_vms.log"
    if log_path.exists():
        log_path.unlink()

    pipeline_t0 = time.time()

    # ─── 파이프라인 진행 ───
    # 분석자 보고서 5단계 절차 (논문 4장 제3절) 와 매핑:
    #   [1/5] OSD 식별                     → step_a + step_b
    #   [2/5] BlueStore 메타데이터 영역 복원 → step_d + step_e1 + step_e5
    #   [3/5] 키-값 저장소 통합              → step_f
    #   [4/5] 가상머신 메타데이터 회수        → step_g
    #   [5/5] 가상머신 디스크 재조립          → step_i (가상머신 마다 반복)
    print("[1/5] OSD 식별 중 ...", flush=True)
    if run_step(LIB_DIR / "step_a_locate_label.py", env, log_path) != 0:
        print(f"ERROR: 단계 A 실패. 로그: {log_path}", file=sys.stderr)
        return 1
    if run_step(LIB_DIR / "step_b_decode_label.py", env, log_path) != 0:
        print(f"ERROR: 단계 B 실패. 로그: {log_path}", file=sys.stderr)
        return 1

    if not args.skip_bluefs:
        print("[2/5] BlueStore 메타데이터 영역 복원 중 ...", flush=True)
        if run_step(LIB_DIR / "step_e1_extract_rocksdb.py", env, log_path) != 0:
            print(f"ERROR: 단계 D+E1 실패. 로그: {log_path}", file=sys.stderr)
            return 1
    if not args.skip_wal:
        if run_step(LIB_DIR / "step_e5_wal_parser.py", env, log_path) != 0:
            print(f"ERROR: 단계 E5 실패. 로그: {log_path}", file=sys.stderr)
            return 1

    print("[3/5] 키-값 저장소 통합 중 ...", flush=True)
    if run_step(LIB_DIR / "step_f_sst_wal_union.py", env, log_path) != 0:
        print(f"ERROR: 단계 F 실패. 로그: {log_path}", file=sys.stderr)
        return 1

    print("[4/5] 가상머신 메타데이터 회수 중 ...", flush=True)
    if run_step(LIB_DIR / "step_g_rbd_header.py", env, log_path) != 0:
        print(f"ERROR: 단계 G 실패. 로그: {log_path}", file=sys.stderr)
        return 1

    # 활성 image 식별
    f_data = load_json(args.output / "_f_results" / "f_union_summary.json")
    active_images = extract_active_images(f_data)
    if not active_images:
        print("ERROR: 활성 가상머신을 발견하지 못함. OSD raw 안에 RBD 가상머신이 없거나 "
              "rbd_directory 가 손상되었을 수 있다.", file=sys.stderr)
        return 1

    if args.image_id:
        requested = set(args.image_id)
        filtered = {iid: nm for iid, nm in active_images.items() if iid in requested}
        if not filtered:
            print(f"ERROR: --image-id 로 지정한 image 가 활성 목록에 없다.\n"
                  f"  요청: {sorted(requested)}\n"
                  f"  활성: {sorted(active_images)}", file=sys.stderr)
            return 1
        active_images = filtered

    print(f"[5/5] 가상머신 디스크 재조립 중 ({len(active_images)} 개) ...", flush=True)
    recovered: list[tuple[str, str, int, str, Path]] = []
    for image_id, vm_name in sorted(active_images.items()):
        print(f"      ▸ {vm_name} ({image_id})", flush=True)
        rc = run_step(LIB_DIR / "step_i_union_5osd.py", env, log_path, extra_args=[image_id])
        if rc != 0:
            print(f"        FAIL — 자세한 내용은 로그({log_path}) 참조", file=sys.stderr)
            continue

        short_name = re.sub(r"-disk-\d+$", "", vm_name)
        candidates = [
            args.output / "_i_results" / f"{vm_name}_union.raw",
            args.output / "_i_results" / f"{short_name}_union.raw",
        ]
        union_path = next((p for p in candidates if p.exists()), None)
        if union_path is None:
            alt = list((args.output / "_i_results").glob(f"{short_name}*_union.raw"))
            if alt:
                union_path = alt[0]
            else:
                print(f"        WARN: 출력 파일 미발견", file=sys.stderr)
                continue

        size = union_path.stat().st_size
        sha = sha256_streaming(union_path)
        recovered.append((image_id, vm_name, size, sha, union_path))

    pipeline_elapsed = time.time() - pipeline_t0

    # ─── 분석자 보고서 출력 ───
    print()
    print("=" * 100)
    print("  [표 1] OSD 식별 (BlueStore Label 디코드 결과)")
    print("=" * 100)
    b_summary = load_json(args.output / "_b_results" / "b_summary.json")
    if b_summary:
        print(f"  {'OSD raw 이미지':<14}  {'ceph_fsid':<36}  {'osd_uuid':<36}  "
              f"{'whoami':>6}  {'상태':<20}")
        print(f"  {'-'*14}  {'-'*36}  {'-'*36}  {'-'*6}  {'-'*20}")
        for raw_name in sorted(b_summary.keys()):
            entry = b_summary[raw_name]
            status = entry.get("status") or "unknown"
            status_display = "정상" if status == "ok" else status
            print(f"  {raw_name:<14}  {(entry.get('ceph_fsid') or '-'):<36}  "
                  f"{(entry.get('osd_uuid') or '-'):<36}  "
                  f"{str(entry.get('whoami') if entry.get('whoami') is not None else '-'):>6}  "
                  f"{status_display:<20}")
    else:
        print("  (단계 B 결과 없음)")

    print()
    print("=" * 100)
    print("  [표 2] 회수된 가상머신")
    print("=" * 100)
    if recovered:
        print(f"  {'image_id':<18}  {'vm_name':<24}  {'image_size':>14}  {'SHA-256':<64}")
        print(f"  {'-'*18}  {'-'*24}  {'-'*14}  {'-'*64}")
        for image_id, vm_name, size, sha, _path in recovered:
            print(f"  {image_id:<18}  {vm_name:<24}  {size:>14,}  {sha}")
        print(f"\n  총 회수: {len(recovered)} 개 가상머신")
    else:
        print("  (회수된 가상머신 없음)")

    # ─── 삭제된 가상머신 잔재 ───
    g_data = load_json(args.output / "_g_results" / "g_summary.json")
    analyzed_image_ids: set[str] = set()
    for osd_name, per_image in g_data.items():
        if isinstance(per_image, dict):
            analyzed_image_ids.update(per_image.keys())
    active_ids = set(active_images.keys())
    orphan_ids = sorted(analyzed_image_ids - active_ids)

    if orphan_ids:
        print()
        print("=" * 100)
        print("  [표 3] 삭제된 가상머신 잔재 (rbd_directory 에서 사라졌으나 OSD 에 흔적이 남음)")
        print("=" * 100)
        print(f"  {'image_id':<18}  {'rbd_header':<11}  {'chunk 흔적 OSD':<24}  "
              f"{'흔적 chunk':>11}  {'잔존 chunk':>11}")
        print(f"  {'-'*18}  {'-'*11}  {'-'*24}  {'-'*11}  {'-'*11}")
        for image_id in orphan_ids:
            header_present = False
            for osd_name, per_image in g_data.items():
                if isinstance(per_image, dict):
                    entry = per_image.get(image_id) or {}
                    if entry.get("header_onode_present"):
                        header_present = True
                        break
            holders, max_trace, max_final = chunk_traces(f_data, image_id)
            print(f"  {image_id:<18}  {('잔존' if header_present else '소실'):<11}  "
                  f"{(', '.join(holders) or '-'):<24}  "
                  f"{max_trace:>11,}  {max_final:>11,}")

    # ─── 출력 위치·시간 ───
    print()
    print(f"  출력 raw : {args.output / '_i_results'}")
    print(f"  분석 로그: {log_path}")
    print(f"  총 소요  : {pipeline_elapsed/60:.1f} 분")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
