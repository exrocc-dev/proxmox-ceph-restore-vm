#!/usr/bin/env python3
"""
restore_vms.py — Recover RBD virtual machine disks from inactive OSD raw images

This tool provides, as a single CLI entry point, the recovery mechanism from
the master's thesis "Recovering Data from Distributed Object Storage in an
Inactive State — Focused on the Proxmox-Ceph Environment" (Donghyun Seok,
Sungkyunkwan University, 2026).

It recovers RBD virtual machine disks byte-for-byte using only the raw images
of OSD disks, without an active Ceph cluster or any external tool to mount the
disks.

Usage:
  python restore_vms.py --osd-dir /path/to/osd/images --output /path/to/output

  # Recover a specific virtual machine only
  python restore_vms.py --osd-dir ./osds --output ./recovered \\
                        --image-id fbabeb6914038

Arguments:
  --osd-dir          Directory holding the OSD raw images. *.001, *.raw, *.img auto-discovered
  --output           Output directory for the recovery results (created automatically)
  --osd-glob         OSD file glob patterns (semicolon-separated, default *.001;*.raw;*.img)
  --image-id         Recover only the given image_id (repeatable)
  --skip-bluefs      Skip BlueStore metadata-region recovery (reuse already-extracted RocksDB)
  --skip-wal         Skip RocksDB WAL parsing (already extracted)

Dependencies:
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

# Avoid mojibake on the Windows (cp949) console
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
    """Run a step module as a subprocess. stdout/stderr are redirected to the log file.

    Nothing is printed to the screen; open log_path directly when debugging.
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
    """Extract the active image_id -> vm_name mapping from the stage F result."""
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
    """Per-OSD trace statistics for an image_id.

    Defines the sum of SST onode residue and WAL PUT as the "trace chunk" count,
    and the number surviving after WAL DEL as the "residual chunk" count. The
    analyst compares the two to gauge how far cleanup has progressed.

    Returns:
      (OSDs where a trace was found, max trace chunks per OSD, max residual chunks per OSD)
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
        description="Inactive OSD raw -> RBD VM disk recovery (Proxmox-Ceph)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--osd-dir", required=True, type=Path,
                        help="Directory holding the OSD raw images")
    parser.add_argument("--output", required=True, type=Path,
                        help="Output directory for the recovery results (created automatically)")
    parser.add_argument("--osd-glob", default="*.001;*.raw;*.img",
                        help="OSD raw file glob patterns (semicolon-separated; default *.001;*.raw;*.img)")
    parser.add_argument("--image-id", action="append", default=None,
                        help="Recover only the given image_id (repeatable; default: all active VMs)")
    parser.add_argument("--skip-bluefs", action="store_true",
                        help="Skip BlueStore metadata-region recovery (reuse already-extracted RocksDB)")
    parser.add_argument("--skip-wal", action="store_true",
                        help="Skip RocksDB WAL parsing (already extracted)")
    args = parser.parse_args()

    if not args.osd_dir.exists() or not args.osd_dir.is_dir():
        print(f"ERROR: --osd-dir is not a directory: {args.osd_dir}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)

    glob_patterns = [p.strip() for p in args.osd_glob.split(";") if p.strip()]
    osd_files = discover_osd_files(args.osd_dir, glob_patterns)
    if not osd_files:
        print(f"ERROR: no OSD raw images found. dir={args.osd_dir}, "
              f"glob='{args.osd_glob}'", file=sys.stderr)
        return 2

    print()
    print(f"  OSD raw directory: {args.osd_dir}")
    print(f"  Output directory : {args.output}")
    print(f"  OSD raw images   : {len(osd_files)}")
    for p in osd_files:
        size_mib = p.stat().st_size / 1024 / 1024
        print(f"    - {p.name}  ({size_mib:,.0f} MiB)")
    print()

    # set up the environment for subprocess calls
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

    # ─── pipeline ───
    # Mapping to the 5-step analyst procedure (thesis Ch.4 Sec.3):
    #   [1/5] OSD identification            -> step_a + step_b
    #   [2/5] BlueStore metadata recovery   -> step_d + step_e1 + step_e5
    #   [3/5] key-value store merge         -> step_f
    #   [4/5] VM metadata recovery          -> step_g
    #   [5/5] VM disk reassembly            -> step_i (repeated per VM)
    print("[1/5] Identifying OSDs ...", flush=True)
    if run_step(LIB_DIR / "step_a_locate_label.py", env, log_path) != 0:
        print(f"ERROR: stage A failed. Log: {log_path}", file=sys.stderr)
        return 1
    if run_step(LIB_DIR / "step_b_decode_label.py", env, log_path) != 0:
        print(f"ERROR: stage B failed. Log: {log_path}", file=sys.stderr)
        return 1

    if not args.skip_bluefs:
        print("[2/5] Recovering BlueStore metadata region ...", flush=True)
        if run_step(LIB_DIR / "step_e1_extract_rocksdb.py", env, log_path) != 0:
            print(f"ERROR: stage D+E1 failed. Log: {log_path}", file=sys.stderr)
            return 1
    if not args.skip_wal:
        if run_step(LIB_DIR / "step_e5_wal_parser.py", env, log_path) != 0:
            print(f"ERROR: stage E5 failed. Log: {log_path}", file=sys.stderr)
            return 1

    print("[3/5] Merging key-value store ...", flush=True)
    if run_step(LIB_DIR / "step_f_sst_wal_union.py", env, log_path) != 0:
        print(f"ERROR: stage F failed. Log: {log_path}", file=sys.stderr)
        return 1

    print("[4/5] Recovering virtual machine metadata ...", flush=True)
    if run_step(LIB_DIR / "step_g_rbd_header.py", env, log_path) != 0:
        print(f"ERROR: stage G failed. Log: {log_path}", file=sys.stderr)
        return 1

    # identify active images
    f_data = load_json(args.output / "_f_results" / "f_union_summary.json")
    active_images = extract_active_images(f_data)
    if not active_images:
        print("ERROR: no active virtual machine found. The OSD raw images may contain no "
              "RBD virtual machine, or rbd_directory may be damaged.", file=sys.stderr)
        return 1

    if args.image_id:
        requested = set(args.image_id)
        filtered = {iid: nm for iid, nm in active_images.items() if iid in requested}
        if not filtered:
            print(f"ERROR: the image(s) given by --image-id are not in the active list.\n"
                  f"  requested: {sorted(requested)}\n"
                  f"  active   : {sorted(active_images)}", file=sys.stderr)
            return 1
        active_images = filtered

    print(f"[5/5] Reassembling virtual machine disks ({len(active_images)}) ...", flush=True)
    recovered: list[tuple[str, str, int, str, Path]] = []
    for image_id, vm_name in sorted(active_images.items()):
        print(f"      > {vm_name} ({image_id})", flush=True)
        rc = run_step(LIB_DIR / "step_i_union_5osd.py", env, log_path, extra_args=[image_id])
        if rc != 0:
            print(f"        FAIL - see the log ({log_path}) for details", file=sys.stderr)
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
                print(f"        WARN: output file not found", file=sys.stderr)
                continue

        size = union_path.stat().st_size
        sha = sha256_streaming(union_path)
        recovered.append((image_id, vm_name, size, sha, union_path))

    pipeline_elapsed = time.time() - pipeline_t0

    # ─── analyst report output ───
    print()
    print("=" * 100)
    print("  [Table 1] OSD identification (BlueStore Label decode result)")
    print("=" * 100)
    b_summary = load_json(args.output / "_b_results" / "b_summary.json")
    if b_summary:
        print(f"  {'OSD raw image':<14}  {'ceph_fsid':<36}  {'osd_uuid':<36}  "
              f"{'whoami':>6}  {'status':<20}")
        print(f"  {'-'*14}  {'-'*36}  {'-'*36}  {'-'*6}  {'-'*20}")
        for raw_name in sorted(b_summary.keys()):
            entry = b_summary[raw_name]
            status = entry.get("status") or "unknown"
            status_display = "ok" if status == "ok" else status
            print(f"  {raw_name:<14}  {(entry.get('ceph_fsid') or '-'):<36}  "
                  f"{(entry.get('osd_uuid') or '-'):<36}  "
                  f"{str(entry.get('whoami') if entry.get('whoami') is not None else '-'):>6}  "
                  f"{status_display:<20}")
    else:
        print("  (no stage B result)")

    print()
    print("=" * 100)
    print("  [Table 2] Recovered virtual machines")
    print("=" * 100)
    if recovered:
        print(f"  {'image_id':<18}  {'vm_name':<24}  {'image_size':>14}  {'SHA-256':<64}")
        print(f"  {'-'*18}  {'-'*24}  {'-'*14}  {'-'*64}")
        for image_id, vm_name, size, sha, _path in recovered:
            print(f"  {image_id:<18}  {vm_name:<24}  {size:>14,}  {sha}")
        print(f"\n  Total recovered: {len(recovered)} virtual machine(s)")
    else:
        print("  (no virtual machine recovered)")

    # ─── deleted virtual machine residue ───
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
        print("  [Table 3] Deleted virtual machine residue (gone from rbd_directory but traces remain on OSD)")
        print("=" * 100)
        print(f"  {'image_id':<18}  {'rbd_header':<11}  {'chunk trace OSD':<24}  "
              f"{'trace chunks':>13}  {'residual chunks':>16}")
        print(f"  {'-'*18}  {'-'*11}  {'-'*24}  {'-'*13}  {'-'*16}")
        for image_id in orphan_ids:
            header_present = False
            for osd_name, per_image in g_data.items():
                if isinstance(per_image, dict):
                    entry = per_image.get(image_id) or {}
                    if entry.get("header_onode_present"):
                        header_present = True
                        break
            holders, max_trace, max_final = chunk_traces(f_data, image_id)
            print(f"  {image_id:<18}  {('present' if header_present else 'lost'):<11}  "
                  f"{(', '.join(holders) or '-'):<24}  "
                  f"{max_trace:>13,}  {max_final:>16,}")

    # ─── output location and elapsed time ───
    print()
    print(f"  Output raw  : {args.output / '_i_results'}")
    print(f"  Analysis log: {log_path}")
    print(f"  Total time  : {pipeline_elapsed/60:.1f} min")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
