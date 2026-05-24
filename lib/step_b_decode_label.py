"""
단계 B — BlueStore label decode (cluster_fsid·whoami·meta map 추출)

목적: 단계 A 에서 PV-FULL-DUMP 확정 → LV-relative 0 = PV-relative 0x100000.
      그 위치의 4 KiB label block 을 decode 하여 osd_uuid·meta map 의
      ceph_fsid·whoami 등 추출. 3 OSD cross-check.

R8: read-only.
근거: 06.md §1.2 verbatim from bluestore_types.cc::bluestore_bdev_label_t::encode
      (preamble 60 byte + ENCODE_START(2,1) + body + CRC32C + zero pad)
"""
from pathlib import Path
import json
import zlib   # for CRC32 (BlueStore uses CRC32C — note difference, see comment)

LV_OFFSET_IN_PV = 0x100000   # 단계 A 에서 결정
LABEL_BLOCK_SIZE = 4096

import sys
sys.path.insert(0, str(Path(__file__).parent))
from _dataset_path import RAW_DIR, EXTRACTED_BASE, OSD_RAW
RAWS = [p.name for p in sorted(OSD_RAW.values(), key=lambda x: x.name)]


def decode_label(buf: bytes) -> dict:
    """4 KiB label block 을 decode."""
    assert len(buf) == LABEL_BLOCK_SIZE
    out = {}

    # ASCII preamble: 60 byte
    if buf[:23] != b"bluestore block device\n":
        raise ValueError(f"missing magic at offset 0: {buf[:23]!r}")
    out["preamble_magic"] = buf[:23].decode("ascii")
    out["preamble_osd_uuid_ascii"] = buf[23:59].decode("ascii")
    if buf[59] != 0x0A:
        raise ValueError(f"missing LF at offset 59: {buf[59]:#x}")

    # ENCODE_START(2, 1): 6 byte header at offset 60
    struct_v = buf[60]
    struct_compat = buf[61]
    struct_len = int.from_bytes(buf[62:66], "little")
    out["struct_v"] = struct_v
    out["struct_compat"] = struct_compat
    out["struct_len"] = struct_len

    # body
    body_start = 66
    body_end = body_start + struct_len
    if body_end > LABEL_BLOCK_SIZE:
        raise ValueError(f"struct_len {struct_len} overflows label block")
    body = buf[body_start:body_end]

    off = 0
    # osd_uuid (16 byte raw)
    osd_uuid_raw = body[off:off + 16]; off += 16
    # 8-4-4-4-12 ASCII form
    h = osd_uuid_raw.hex()
    out["osd_uuid_raw_hex"] = h
    out["osd_uuid"] = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    # size (u64 LE)
    out["size"] = int.from_bytes(body[off:off + 8], "little"); off += 8

    # btime: utime_t (u32 sec LE + u32 nsec LE)
    btime_sec = int.from_bytes(body[off:off + 4], "little"); off += 4
    btime_nsec = int.from_bytes(body[off:off + 4], "little"); off += 4
    out["btime_sec"] = btime_sec
    out["btime_nsec"] = btime_nsec

    # description: u32 LE len + ASCII
    desc_len = int.from_bytes(body[off:off + 4], "little"); off += 4
    out["description"] = body[off:off + desc_len].decode("ascii", errors="replace")
    off += desc_len

    # meta map: u32 LE count + N×(u32 LE klen + key + u32 LE vlen + val)
    meta_count = int.from_bytes(body[off:off + 4], "little"); off += 4
    meta = {}
    for _ in range(meta_count):
        klen = int.from_bytes(body[off:off + 4], "little"); off += 4
        k = body[off:off + klen].decode("ascii", errors="replace"); off += klen
        vlen = int.from_bytes(body[off:off + 4], "little"); off += 4
        v = body[off:off + vlen].decode("ascii", errors="replace"); off += vlen
        meta[k] = v
    out["meta"] = meta
    out["body_consumed"] = off
    out["body_remaining"] = struct_len - off

    # CRC32C (4 byte LE) follows the struct (after struct_len bytes from body_start)
    # Note: BlueStore uses CRC32C (Castagnoli), not zlib's CRC32. zlib.crc32 will
    # NOT match; we record the bytes for later cross-check with a CRC32C impl.
    crc_bytes = buf[body_end:body_end + 4]
    out["crc32c_stored_le"] = crc_bytes.hex()
    out["crc32c_stored_value"] = int.from_bytes(crc_bytes, "little")

    return out


def main():
    print("=" * 76)
    print("단계 B — BlueStore label decode")
    print(f"Label position: PV-relative 0x{LV_OFFSET_IN_PV:x} (= LV-relative 0x0)")
    print(f"Block size:     {LABEL_BLOCK_SIZE} byte (4 KiB)")
    print("=" * 76)

    results = {}
    decode_status: dict[str, str] = {}  # raw_name → "ok" | "file_not_found" | "decode_failed: <reason>"
    for raw_name in RAWS:
        path = RAW_DIR / raw_name
        if not path.exists():
            print(f"\n{raw_name}: FILE NOT FOUND")
            decode_status[raw_name] = "file_not_found"
            continue
        with open(path, "rb") as f:
            f.seek(LV_OFFSET_IN_PV)
            label_block = f.read(LABEL_BLOCK_SIZE)
        try:
            decoded = decode_label(label_block)
        except ValueError as e:
            print(f"\n{raw_name}: DECODE FAILED — {e}")
            decode_status[raw_name] = f"decode_failed: {e}"
            continue
        decode_status[raw_name] = "ok"

        print(f"\n{raw_name}:")
        print(f"  struct_v / compat / len:  v={decoded['struct_v']} compat={decoded['struct_compat']} len={decoded['struct_len']}")
        print(f"  osd_uuid (preamble):      {decoded['preamble_osd_uuid_ascii']}")
        print(f"  osd_uuid (body raw):      {decoded['osd_uuid']}")
        match = "✓ match" if decoded['preamble_osd_uuid_ascii'] == decoded['osd_uuid'] else "✗ MISMATCH"
        print(f"                            {match} (preamble vs body raw)")
        print(f"  device size (label):      {decoded['size']:,} byte ({decoded['size'] / 1024**3:.2f} GiB)")
        print(f"  btime:                    sec={decoded['btime_sec']} nsec={decoded['btime_nsec']}")
        print(f"  description:              {decoded['description']!r}")
        print(f"  meta map ({len(decoded['meta'])} keys):")
        for k, v in sorted(decoded['meta'].items()):
            # truncate long values (osd_key) for display
            disp = v if len(v) <= 60 else v[:57] + "..."
            print(f"    {k:20s} = {disp!r}")
        print(f"  body bytes consumed:      {decoded['body_consumed']} of {decoded['struct_len']}")
        print(f"  CRC32C stored (LE hex):   {decoded['crc32c_stored_le']}")
        results[raw_name] = decoded

    # Cross-check
    print()
    print("=" * 76)
    print("CROSS-CHECK")
    print("=" * 76)

    # 1) ceph_fsid same across all 3 OSDs?
    fsids = {n: r["meta"].get("ceph_fsid", "<missing>") for n, r in results.items()}
    print("\nceph_fsid per OSD:")
    for n, fsid in fsids.items():
        print(f"  {n}: {fsid}")
    unique_fsids = set(fsids.values())
    if len(unique_fsids) == 1:
        print(f"  → ALL SAME cluster: {unique_fsids.pop()}")
    else:
        print(f"  → INCONSISTENT: {unique_fsids}")

    # 2) whoami per OSD
    print("\nwhoami (osd_id) per OSD:")
    for n, r in results.items():
        print(f"  {n}: {r['meta'].get('whoami', '<missing>')}")

    # ─── JSON 저장 — restore_vms.py 가 분석자 보고서 OSD 식별 표에 사용 ───
    out_dir = EXTRACTED_BASE / "_b_results"
    out_dir.mkdir(exist_ok=True)
    summary = {}
    for raw_name in RAWS:
        status = decode_status.get(raw_name, "unknown")
        decoded = results.get(raw_name)
        if decoded is not None:
            meta = decoded.get("meta") or {}
            summary[raw_name] = {
                "status": status,
                "osd_uuid": decoded.get("osd_uuid"),
                "ceph_fsid": meta.get("ceph_fsid"),
                "whoami": meta.get("whoami"),
                "device_size": decoded.get("size"),
            }
        else:
            summary[raw_name] = {
                "status": status,
                "osd_uuid": None, "ceph_fsid": None, "whoami": None, "device_size": None,
            }
    out_json = out_dir / "b_summary.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON 저장: {out_json}")


if __name__ == "__main__":
    main()
