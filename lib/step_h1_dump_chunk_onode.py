"""
단계 H-1 — vm-104 의 첫 sparse chunk onode 1 개 byte 구조 측정

목적:
  1. 한 chunk 의 onode key/value byte 전체 dump
  2. bluestore_onode_t 구조 (06.md §6) 따라 nid·size·attrs·flags·extent_map_shards parsing
  3. attrs["_"] 위치 + object_info_t 의 data_digest field 까지 도달
  4. extent_map (inline 또는 spanning) 위치 파악
  5. 본 dump 을 H-2 (data_digest) / H-3 (blob/pextent) 진행 입력

대상: osd.1 또는 osd.2 의 SST 안 vm-104 의 첫 chunk (가장 sparse 한 image, 174 chunks)
"""
import sys
import struct
import hashlib
from pathlib import Path
from rocksdict import Rdict, Options, AccessType

sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import read_denc_varint
from step_f_sst_wal_union import open_readonly

from _dataset_path import EXTRACTED_BASE

TARGET_PATTERN = b"rbd_data.fbabeb6914038."   # vm-104 chunks
TARGET_OSDS = ["osd.1", "osd.2"]   # SST 에 있는 OSD 들 (단계 G 의 SST presence)


def hex_repr(b: bytes, max_len: int = 200) -> str:
    h = b[:max_len].hex()
    if len(b) > max_len:
        h += f"...(+{len(b) - max_len})"
    return h


def ascii_repr(b: bytes, max_len: int = 200) -> str:
    s = b[:max_len]
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in s) + (
        f"...(+{len(b) - max_len})" if len(b) > max_len else "")


def find_first_chunk_onode(db, cf_list, pattern: bytes):
    """O-* CF 안 pattern 매치 첫 chunk onode."""
    matches = []
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if pattern in key:
                value = bytes(it.value())
                matches.append((cf_name, key, value))
                if len(matches) >= 5:   # 5 sample 만 보자
                    return matches
            it.next()
    return matches


def parse_onode(value: bytes) -> dict:
    """bluestore_onode_t DENC parsing (06.md §6.1 spec).
       wire: 6 byte header + varint(nid) + varint(size) + attrs + flags + extent_map_shards + ...
    """
    out = {"raw_len": len(value)}
    if len(value) < 6:
        out["error"] = "too short"
        return out

    sv = value[0]; sc = value[1]
    sl = struct.unpack_from("<I", value, 2)[0]
    out["struct_v"] = sv
    out["struct_compat"] = sc
    out["struct_len"] = sl

    body_start = 6
    body_end = body_start + sl
    if body_end > len(value):
        out["error"] = f"struct_len {sl} > value tail {len(value) - body_start}"
        body_end = len(value)
    body = value[body_start:body_end]
    out["body_len"] = len(body)

    off = 0
    nid, off = read_denc_varint(body, off)
    size, off = read_denc_varint(body, off)
    out["nid"] = nid
    out["size"] = size

    # attrs map: u32 LE count + count × (u32 LE klen + key + u32 LE plen + ptr)
    if off + 4 > len(body):
        out["error_attrs"] = "no attrs count"
        return out
    n_attrs = struct.unpack_from("<I", body, off)[0]; off += 4
    out["n_attrs"] = n_attrs
    attrs = {}
    attr_offsets = {}
    for i in range(n_attrs):
        if off + 4 > len(body):
            out["error_attrs"] = f"truncated at attr {i} key len"
            return out
        klen = struct.unpack_from("<I", body, off)[0]; off += 4
        if off + klen > len(body):
            out["error_attrs"] = f"truncated at attr {i} key body"
            return out
        key = body[off:off + klen]; off += klen
        if off + 4 > len(body):
            out["error_attrs"] = f"truncated at attr {i} ptr len"
            return out
        plen = struct.unpack_from("<I", body, off)[0]; off += 4
        if off + plen > len(body):
            out["error_attrs"] = f"truncated at attr {i} ptr body"
            return out
        ptr_start_in_body = off
        ptr = body[off:off + plen]; off += plen
        attrs[key] = ptr
        # 절대 offset (value 기준)
        attr_offsets[key] = body_start + ptr_start_in_body
    out["attrs"] = attrs
    out["attr_offsets"] = attr_offsets

    # flags (u8)
    if off >= len(body):
        out["error"] = "no flags"
        return out
    flags = body[off]; off += 1
    out["flags"] = flags
    fl_names = []
    if flags & 1: fl_names.append("OMAP")
    if flags & 2: fl_names.append("PGMETA_OMAP")
    if flags & 4: fl_names.append("PERPOOL_OMAP")
    if flags & 8: fl_names.append("PERPG_OMAP")
    out["flag_names"] = fl_names

    # extent_map_shards: u32 LE count + count × (varint offset + varint bytes)
    if off + 4 > len(body):
        out["error"] = "no extent_map_shards count"
        return out
    n_shards = struct.unpack_from("<I", body, off)[0]; off += 4
    out["n_shards"] = n_shards
    shards = []
    for i in range(n_shards):
        sh_offset, off = read_denc_varint(body, off)
        sh_bytes,  off = read_denc_varint(body, off)
        shards.append({"offset": sh_offset, "bytes": sh_bytes})
    out["extent_map_shards"] = shards

    out["after_shards_off_in_body"] = off
    out["after_shards_off_abs"] = body_start + off
    out["body_remaining_after_shards"] = len(body) - off

    # rest = expected_object_size + expected_write_size + alloc_hint_flags + zone_offset_refs
    # OR: if n_shards == 0, then inline extent_map follows after these fields
    # Read all remaining DENC fields
    try:
        eos, off = read_denc_varint(body, off)
        ews, off = read_denc_varint(body, off)
        ahf, off = read_denc_varint(body, off)
        out["expected_object_size"] = eos
        out["expected_write_size"] = ews
        out["alloc_hint_flags"] = ahf
    except (IndexError, ValueError) as e:
        out["error_eos"] = str(e)
    # zone_offset_refs (struct_v >= 2): u32 LE count + entries
    if off + 4 <= len(body) and out.get("struct_v", 0) >= 2:
        zor_count = struct.unpack_from("<I", body, off)[0]; off += 4
        out["zone_offset_refs_count"] = zor_count
        for i in range(zor_count):
            if off + 12 <= len(body):
                z = struct.unpack_from("<I", body, off)[0]; off += 4
                v = struct.unpack_from("<Q", body, off)[0]; off += 8

    out["body_consumed_after_DENC_FINISH"] = off
    out["body_remaining_after_DENC_FINISH"] = len(body) - off

    # value 안 body 뒤 trailing bytes (DENC 의 tail 또는 extra)
    out["value_tail_after_body"] = len(value) - body_end

    return out


def main():
    print("=" * 100)
    print("단계 H-1 — vm-104 의 첫 chunk onode byte 구조 측정")
    print("=" * 100)

    OUT_DIR = EXTRACTED_BASE / "_h_results"
    OUT_DIR.mkdir(exist_ok=True)

    for osd in TARGET_OSDS:
        db_dir = EXTRACTED_BASE / osd / "db"
        print(f"\n{'─' * 100}")
        print(f"  {osd}  ({db_dir})")
        print(f"{'─' * 100}")

        db, cf_list = open_readonly(db_dir)
        matches = find_first_chunk_onode(db, cf_list, TARGET_PATTERN)
        print(f"\n  pattern={TARGET_PATTERN!r}: {len(matches)} matches in O-* CFs (first 5)")

        for i, (cf_name, key, value) in enumerate(matches):
            print(f"\n  [{i}] cf={cf_name}")
            print(f"      key  ({len(key)}b): {hex_repr(key, 100)}")
            print(f"      key  ASCII:        {ascii_repr(key, 100)}")
            print(f"      value ({len(value)}b): {hex_repr(value, 80)}")
            parsed = parse_onode(value)
            print(f"      parsed:")
            for k, v in parsed.items():
                if k == "attrs":
                    print(f"        attrs ({len(v)} entries):")
                    for ak, av in v.items():
                        print(f"          key={ak.decode('latin-1', errors='replace')!r:<10s} ({len(ak)}b) → ptr ({len(av)}b)  hex={hex_repr(av, 40)}")
                elif k == "attr_offsets":
                    pass
                elif k == "extent_map_shards":
                    print(f"        extent_map_shards ({len(v)}):")
                    for s in v:
                        print(f"          offset=0x{s['offset']:x}  bytes={s['bytes']}")
                else:
                    print(f"        {k}: {v}")

            # 첫 sample 만 raw 저장
            if i == 0:
                out_file = OUT_DIR / f"{osd}_vm104_first_chunk.bin"
                with open(out_file, "wb") as f:
                    f.write(b"# osd: " + osd.encode() + b"\n")
                    f.write(f"# cf: {cf_name}\n".encode())
                    f.write(f"# key_len: {len(key)}\n".encode())
                    f.write(f"# value_len: {len(value)}\n".encode())
                    f.write(b"#--KEY--\n"); f.write(key)
                    f.write(b"\n#--VALUE--\n"); f.write(value)
                print(f"\n      raw saved: {out_file.name}")

                # 만약 attrs["_"] 가 있다면 그 시작 offset 도 출력
                if b"_" in parsed.get("attrs", {}):
                    oi_ptr = parsed["attrs"][b"_"]
                    oi_off = parsed["attr_offsets"][b"_"]
                    print(f"\n      object_info_t (attrs[\"_\"]): offset_in_value=0x{oi_off:x}, len={len(oi_ptr)}")
                    print(f"        first 64b hex: {oi_ptr[:64].hex()}")
                    print(f"        first 64b asc: {ascii_repr(oi_ptr, 64)}")

                # spanning shards 가 있으면 그 키들도 fetch
                if parsed.get("n_shards", 0) > 0:
                    print(f"\n      spanning shards 가 {parsed['n_shards']} 개 — 각 key 는 onode_key + u32 BE offset + 'x':")
                    for s in parsed["extent_map_shards"]:
                        shard_key = key + struct.pack(">I", s['offset']) + b"x"
                        # 같은 CF 에서 fetch
                        cf_obj = db.get_column_family(cf_name)
                        sv = cf_obj.get(shard_key)
                        sv_bytes = bytes(sv) if sv is not None else None
                        if sv_bytes is None:
                            print(f"        shard offset=0x{s['offset']:x}: NOT FOUND")
                        else:
                            print(f"        shard offset=0x{s['offset']:x}: found, len={len(sv_bytes)}")
                            print(f"          hex {hex_repr(sv_bytes, 80)}")
                else:
                    print(f"\n      n_shards = 0 → inline extent_map (onode value 안 DENC_FINISH 후 tail 또는 별도 영역)")
                    # inline extent_map: extent_map_shards 가 0 이면 별도 위치에 있음
                    # 06.md §10.3 spec: spanning_blobs + extent_map 둘 다 별도 영역. tail 분석 필요.
                    if "value_tail_after_body" in parsed and parsed["value_tail_after_body"] > 0:
                        tail_start = 6 + parsed["struct_len"]
                        tail = value[tail_start:]
                        print(f"      value_tail ({len(tail)}b): {hex_repr(tail, 80)}")
                        print(f"      tail ASCII: {ascii_repr(tail, 80)}")

        db.close()


if __name__ == "__main__":
    main()
