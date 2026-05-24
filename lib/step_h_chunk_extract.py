"""
단계 H — chunk 시범 추출 + 검증 (4 단계 통합)

H-2: object_info_t (attrs["_"]) decode → data_digest 추출 (06.md §10.4)
H-3: extent_map shard parse → bluestore_blob_t → pextents → raw byte 읽기 (06.md §10.1, §10.3)
H-4: SHA-256 + R4 (cross-OSD byte-identical) + CRC32C (vs data_digest) 검증

대상: vm-104 의 첫 chunk (block 0xc4 = 196). 4 MiB full chunk.
osd.1 + osd.2 의 SST 안 같은 chunk 추출 → byte-identical 확인 (R4 oracle).
"""
import sys
import struct
import hashlib
from pathlib import Path
from rocksdict import Rdict, Options, AccessType

sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import read_denc_varint, PV_LV_OFFSET
from step_f_sst_wal_union import open_readonly

from _dataset_path import RAW_DIR, EXTRACTED_BASE, OSD_RAW

# 시범: vm-104, chunk c4
TARGET_PATTERN = b"rbd_data.fbabeb6914038."
TARGET_CHUNK_HEX = "00000000000000c4"   # block 196


# ───── varint_lowz (denc_varint_lowz) ─────
# bluestore 의 length 인코딩: 하위 비트가 0 인 정도를 shift 로 압축
# encode: while (v >= (1<<7)) { ... } 식이 아니라
#   "trailing zero count" 만큼 right-shift 후 varint 인코딩
# decode: 상응 방향
def read_denc_varint_lowz(buf: bytes, off: int) -> tuple[int, int]:
    """denc_varint_lowz — v18.2.8 src/include/denc.h verbatim.
       encode: lowznib = countr_zero(v)/4 (capped 3); v >>= lowznib*4; v <<= 2; v |= lowznib; varint(v)
       decode: x = varint(); lowznib = x & 3; val = (x >> 2) << (lowznib * 4)
    """
    x, off2 = read_denc_varint(buf, off)
    lowznib = x & 3
    val = (x >> 2) << (lowznib * 4)
    return val, off2


# ───── denc_lba (v18.2.8 verbatim from src/include/denc.h) ─────
# 4-byte LE word, optional varint continuation if word bit 31 set
def read_denc_lba(buf: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise IndexError(f"denc_lba needs 4 bytes at offset {off}")
    word = struct.unpack_from("<I", buf, off)[0]
    off += 4
    has_cont = bool(word & 0x80000000)
    word &= 0x7fffffff
    case = word & 7
    if case in (0, 2, 4, 6):
        v = (word & 0x7ffffffe) << (12 - 1)
        shift = 12 + 30
    elif case in (1, 5):
        v = (word & 0x7ffffffc) << (16 - 2)
        shift = 16 + 29
    elif case == 3:
        v = (word & 0x7ffffff8) << (20 - 3)
        shift = 20 + 28
    elif case == 7:
        v = (word & 0x7ffffff8) >> 3
        shift = 28
    else:
        raise ValueError(f"unreachable denc_lba case {case}")
    if has_cont:
        while True:
            b = buf[off]; off += 1
            v |= (b & 0x7f) << shift
            shift += 7
            if not (b & 0x80):
                break
    return v, off


# ───── bluestore_pextent_t parse ─────
def parse_pextent(buf: bytes, off: int) -> tuple[dict, int]:
    """offset = denc_lba, length = denc_varint_lowz."""
    p_offset, off = read_denc_lba(buf, off)
    p_length, off = read_denc_varint_lowz(buf, off)
    return {"offset": p_offset, "length": p_length}, off


# ───── bluestore_blob_t parse (06.md §10.1) ─────
# 헤더 없음. WRITE_CLASS_DENC_FEATURED.
# encode: (1) PExtentVector (u32 LE count + count×pextent)
#         (2) varint flags
#         (3) if compressed: varint_lowz logical_length, varint_lowz compressed_length
#         (4) if csum: u8 csum_type, u8 csum_chunk_order, varint csum_data_len + csum_data raw
#         (5) if has_unused: u16 LE unused
def parse_blob(buf: bytes, off: int) -> tuple[dict, int]:
    """bluestore_blob_t (06.md §10.1 정정 — PExtentVector size 가 varint, NOT u32 LE).
       v18.2.8 src/os/bluestore/bluestore_types.h verbatim:
         denc(extents, p);            ← vector denc_traits 가 size 를 varint 로
         denc_varint(flags, p);
         if (is_compressed()): denc_varint_lowz(logical_length, p), denc_varint_lowz(compressed_length, p)
         if (has_csum()): denc(csum_type, p), denc(csum_chunk_order, p), denc_varint(csum_data.length(), p), raw csum_data
         if (has_unused()): denc(unused, p) ← u16 LE
    """
    out = {}
    # PExtentVector: varint count (NOT u32 LE — 06.md §10.1 spec error)
    n_ext, off = read_denc_varint(buf, off)
    extents = []
    for _ in range(n_ext):
        ext, off = parse_pextent(buf, off)
        extents.append(ext)
    out["extents"] = extents
    # flags varint
    flags, off = read_denc_varint(buf, off)
    out["flags"] = flags
    out["flag_names"] = []
    if flags & 0x01: out["flag_names"].append("MUTABLE")
    if flags & 0x02: out["flag_names"].append("COMPRESSED")
    if flags & 0x04: out["flag_names"].append("CSUM")
    if flags & 0x08: out["flag_names"].append("HAS_UNUSED")
    if flags & 0x10: out["flag_names"].append("SHARED")
    # compressed
    if flags & 0x02:
        out["logical_length"], off = read_denc_varint_lowz(buf, off)
        out["compressed_length"], off = read_denc_varint_lowz(buf, off)
    # csum
    if flags & 0x04:
        if off + 2 > len(buf):
            out["error"] = "truncated csum_type/order"
            return out, off
        out["csum_type"] = buf[off]; off += 1
        out["csum_chunk_order"] = buf[off]; off += 1
        csum_len, off = read_denc_varint(buf, off)
        out["csum_len"] = csum_len
        out["csum_data"] = buf[off:off+csum_len]
        off += csum_len
    # unused
    if flags & 0x08:
        out["unused"], off = struct.unpack_from("<H", buf, off)[0], off + 2
    return out, off


# ───── used_in_blob (bluestore_blob_use_tracker_t) decode ─────
# spec: bluestore_types.h:407-423
def parse_used_in_blob(buf: bytes, off: int) -> tuple[dict, int]:
    out = {}
    au_size, off = read_denc_varint(buf, off)
    out["au_size"] = au_size
    if au_size != 0:
        num_au, off = read_denc_varint(buf, off)
        out["num_au"] = num_au
        if num_au == 0:
            total_bytes, off = read_denc_varint(buf, off)
            out["total_bytes"] = total_bytes
        else:
            bytes_per_au = []
            for _ in range(num_au):
                v, off = read_denc_varint(buf, off)
                bytes_per_au.append(v)
            out["bytes_per_au"] = bytes_per_au
    return out, off


# ───── encode_spanning_blobs decoder (BlueStore.cc:3202-3221) ─────
# format:
#   [u8 struct_v]
#   [varint n]
#   n × {
#     [varint blob_id]
#     [bluestore_blob_t]                 ← parse_blob
#     [if blob.flags & FLAG_SHARED: u64 LE sbid]
#     [if struct_v > 1: bluestore_blob_use_tracker_t (used_in_blob)]
#   }
# k10 정정 (2026-05-10): vm-103 bn=0 의 spanning blob 미참조 결함 fix.
def parse_spanning_blobs(buf: bytes, off: int) -> tuple[dict, int, dict]:
    """spanning_blob_map decoder. 반환: (meta, new_off, blob_map_by_id)."""
    meta = {"raw_off": off}
    if off >= len(buf):
        meta["error"] = "no struct_v"
        return meta, off, {}
    sp_v = buf[off]; off += 1
    meta["struct_v"] = sp_v
    if sp_v not in (1, 2):
        meta["error"] = f"unexpected struct_v={sp_v}"
        return meta, off, {}
    try:
        sp_n, off = read_denc_varint(buf, off)
    except IndexError:
        meta["error"] = "truncated sp_n"
        return meta, off, {}
    meta["sp_n"] = sp_n
    blob_map = {}
    for i in range(sp_n):
        try:
            blob_id, off = read_denc_varint(buf, off)
            blob, off = parse_blob(buf, off)
        except Exception as e:
            meta["error"] = f"spanning blob[{i}] parse: {e}"
            return meta, off, blob_map
        # if FLAG_SHARED, sbid u64 LE
        if blob.get("flags", 0) & 0x10:
            if off + 8 > len(buf):
                meta["error"] = f"spanning blob[{i}] truncated sbid"
                return meta, off, blob_map
            sbid = struct.unpack_from("<Q", buf, off)[0]
            off += 8
            blob["_sbid"] = sbid
        # used_in_blob (struct_v > 1)
        if sp_v > 1:
            try:
                used, off = parse_used_in_blob(buf, off)
                blob["_used_in_blob"] = used
            except Exception as e:
                meta["error"] = f"spanning blob[{i}] used_in_blob: {e}"
                return meta, off, blob_map
        blob["_blob_id"] = blob_id
        blob_map[blob_id] = blob
    meta["consumed_off"] = off
    return meta, off, blob_map


# ───── extent_map shard parse (06.md §10.3) ─────
# [u8 struct_v=2] [varint n_extents] n × extent_record
#
# k7 정정 (2026-05-10):
#   blob 인덱싱은 sequential local_blobs 가 아니라 **extent_pos 키 sparse dict**.
#   - encoding (BlueStore.cc:3094-3097): NEW blob 시 last_encoded_id = n + 1
#     (n = shard 안 0-based extent 인덱스, NEW 만 카운트 아님)
#   - decoding (BlueStore.cc:3163-3174): blobid >>= SHIFT; if blobid:
#     consume_blobid(blobid - 1); else: consume_blob(extent_pos, ...)
#     ; ++extent_pos (매 extent)
#   - storage (BlueStore.cc:3243): blobs.resize(extent_no + 1); blobs[extent_no] = b
#     → sparse vector keyed by 정의 시점 extent_pos
#
# k10 정정 (2026-05-10): spanning blob lookup 추가.
#   - encoding (BlueStore.cc:3091-3093): spanning blob 시 blobid = blob.id << SHIFT | SPANNING_FLAG
#   - decoding (BlueStore.cc:3160-3162): if blobid & SPANNING: consume_blobid(le, true, blobid >> SHIFT)
#   - lookup: spanning_blob_map[blob_id] (decode_spanning_blobs, BlueStore.cc:3202-3221)
def parse_shard(value: bytes, spanning_blob_map: dict | None = None) -> dict:
    out = {"raw_len": len(value)}
    if len(value) < 1:
        out["error"] = "empty"; return out
    sv = value[0]
    out["struct_v"] = sv
    off = 1
    n_ext, off = read_denc_varint(value, off)
    out["n_extents"] = n_ext
    extents = []
    blobs_by_extent_pos: dict[int, dict] = {}   # k7: sparse, keyed by extent_pos
    new_blob_count = 0                          # 진단용 (= len(blobs_by_extent_pos))
    prev_logical_end = 0
    prev_length = 0
    for i in range(n_ext):
        # i 가 곧 extent_pos (Ceph 의 ++extent_pos 매 extent — BlueStore.cc:3174)
        try:
            blobid_raw, off = read_denc_varint(value, off)
        except IndexError:
            out["error"] = f"truncated blobid at extent {i}"; break
        blobid = blobid_raw
        contiguous = bool(blobid & 0x01)
        zerooffset = bool(blobid & 0x02)
        samelength = bool(blobid & 0x04)
        spanning = bool(blobid & 0x08)
        idx = blobid >> 4
        # gap
        if not contiguous:
            gap, off = read_denc_varint_lowz(value, off)
            logical_offset = prev_logical_end + gap
        else:
            logical_offset = prev_logical_end
        # blob_offset
        if not zerooffset:
            blob_offset, off = read_denc_varint_lowz(value, off)
        else:
            blob_offset = 0
        # length
        if not samelength:
            length, off = read_denc_varint_lowz(value, off)
        else:
            length = prev_length
        rec = {
            "logical_offset": logical_offset,
            "blob_offset": blob_offset,
            "length": length,
            "blobid_raw": blobid_raw,
            "spanning": spanning,
            "blob_idx": idx,
            "contiguous": contiguous,
            "zerooffset": zerooffset,
            "samelength": samelength,
        }
        if not spanning and idx == 0:
            # NEW inline local blob — 정의 시점 extent_pos = i 에 sparse 저장
            # (BlueStore.cc:3170 consume_blob(le, extent_pos, sbid, b);
            #  BlueStore.cc:3243 blobs.resize(extent_no + 1); blobs[extent_no] = b)
            blob, off = parse_blob(value, off)
            blobs_by_extent_pos[i] = blob
            new_blob_count += 1
            rec["blob"] = blob
            rec["blob_extent_pos"] = i
            # if blob shared, sbid u64 LE follows
            if blob.get("flags", 0) & 0x10:   # FLAG_SHARED
                rec["sbid"] = struct.unpack_from("<Q", value, off)[0]; off += 8
        elif not spanning:
            # reference: idx = (encoded blobid_idx) → blobs[idx - 1] (BlueStore.cc:3165)
            ref_pos = idx - 1
            if ref_pos in blobs_by_extent_pos:
                rec["blob"] = blobs_by_extent_pos[ref_pos]
                rec["blob_extent_pos"] = ref_pos
            else:
                rec["error"] = (
                    f"blob ref idx={idx} (extent_pos={ref_pos}) not in "
                    f"blobs_by_extent_pos (have keys {sorted(blobs_by_extent_pos.keys())})"
                )
        else:
            # k10 정정: spanning blob — spanning_blob_map[blob_id] lookup
            # (BlueStore.cc:3160-3162: consume_blobid(le, true, blobid >> SHIFT))
            blob_id = idx   # spanning 의 idx 는 blob_id 자체 (subtract 1 안함)
            if spanning_blob_map and blob_id in spanning_blob_map:
                rec["blob"] = spanning_blob_map[blob_id]
                rec["blob_spanning_id"] = blob_id
            else:
                rec["error"] = (
                    f"spanning blob_id={blob_id} not in spanning_blob_map "
                    f"(have keys {sorted(spanning_blob_map.keys()) if spanning_blob_map else []})"
                )
        extents.append(rec)
        prev_logical_end = logical_offset + length
        prev_length = length
    out["extents"] = extents
    out["local_blobs_count"] = new_blob_count       # backward-compat (k3 dump 등 진단)
    out["blobs_by_extent_pos_keys"] = sorted(blobs_by_extent_pos.keys())  # k7 진단용
    out["bytes_consumed"] = off
    out["bytes_remaining"] = len(value) - off
    return out


# ───── object_info_t parse (06.md §10.4) — backward parse ─────
# forward parse 는 variable-length field (legacy_snaps 등) 의 미세한 차이 때문에 불안정.
# trailing 40 byte 가 고정 크기 (flags+local_mtime+data_digest+omap_digest+eos+ews+ahf):
#   flags (4) + local_mtime (8) + data_digest (4) + omap_digest (4)
#   + expected_object_size (8) + expected_write_size (8) + alloc_hint_flags (4) = 40 byte
# manifest 가 있으면 (flags & 0x80 = FLAG_MANIFEST) 그 뒤에 manifest field 추가 — 본 chunk 는 미사용.
# R8: 본 backward parse 는 manifest=없음 가정 — flags 검사로 사후 검증.
def parse_object_info(value: bytes) -> dict:
    """object_info_t backward parse. 24 trailing fields = 40 byte 고정."""
    out = {"raw_len": len(value)}
    if len(value) < 6 + 40:
        out["error"] = "too short"; return out
    sv = value[0]; sc = value[1]
    sl = struct.unpack_from("<I", value, 2)[0]
    out["struct_v"] = sv; out["struct_compat"] = sc; out["struct_len"] = sl
    body = value[6:6+sl]

    # backward parse — body 끝에서 40 byte 고정 trailing
    n = len(body)
    if n < 40:
        out["error"] = "body too short"; return out
    flags_at = n - 40
    out["flags"] = struct.unpack_from("<I", body, flags_at)[0]
    out["flag_names"] = []
    if out["flags"] & 0x01: out["flag_names"].append("LOST")
    if out["flags"] & 0x02: out["flag_names"].append("WHITEOUT")
    if out["flags"] & 0x04: out["flag_names"].append("DIRTY")
    if out["flags"] & 0x08: out["flag_names"].append("OMAP")
    if out["flags"] & 0x10: out["flag_names"].append("DATA_DIGEST")
    if out["flags"] & 0x20: out["flag_names"].append("OMAP_DIGEST")
    if out["flags"] & 0x80: out["flag_names"].append("MANIFEST")
    if out["flags"] & 0x80:
        out["warning"] = "MANIFEST flag set — backward parse 의 trailing offset 가 다를 수 있음"

    lm_sec = struct.unpack_from("<I", body, flags_at + 4)[0]
    lm_nsec = struct.unpack_from("<I", body, flags_at + 8)[0]
    out["local_mtime"] = {"sec": lm_sec, "nsec": lm_nsec}
    out["data_digest"] = struct.unpack_from("<I", body, flags_at + 12)[0]
    out["omap_digest"] = struct.unpack_from("<I", body, flags_at + 16)[0]
    out["expected_object_size"] = struct.unpack_from("<Q", body, flags_at + 20)[0]
    out["expected_write_size"] = struct.unpack_from("<Q", body, flags_at + 28)[0]
    out["alloc_hint_flags"] = struct.unpack_from("<I", body, flags_at + 36)[0]

    # forward parse 도 같이 (size + mtime 추출 위해)
    off = 0
    # soid sub-DENC skip
    if off + 6 > n: out["forward_error"] = "soid header"; return out
    sub_sl = struct.unpack_from("<I", body, off + 2)[0]
    off += 6 + sub_sl
    if off + 6 > n: out["forward_error"] = "myoloc header"; return out
    sub_sl = struct.unpack_from("<I", body, off + 2)[0]
    off += 6 + sub_sl
    if off + 4 > n: return out
    out["category"] = struct.unpack_from("<I", body, off)[0]; off += 4
    out["version_ver"] = struct.unpack_from("<Q", body, off)[0]; off += 8
    out["version_epoch"] = struct.unpack_from("<I", body, off)[0]; off += 4
    out["prior_ver"] = struct.unpack_from("<Q", body, off)[0]; off += 8
    out["prior_epoch"] = struct.unpack_from("<I", body, off)[0]; off += 4
    if off + 6 > n: return out
    sub_sl = struct.unpack_from("<I", body, off + 2)[0]
    off += 6 + sub_sl
    if off + 16 > n: return out
    out["size"] = struct.unpack_from("<Q", body, off)[0]; off += 8
    mt_sec = struct.unpack_from("<I", body, off)[0]; off += 4
    mt_nsec = struct.unpack_from("<I", body, off)[0]; off += 4
    out["mtime"] = {"sec": mt_sec, "nsec": mt_nsec}
    return out


# ───── chunk 추출 ─────
def find_chunk_onode(db, cf_list, target_pattern: bytes, target_chunk_hex: str):
    """O-* CF 안 ASCII 'rbd_data.<id>.<chunk_hex>' 가 들어있고 키 끝이 'o' 인 onode."""
    full_pattern = target_pattern + target_chunk_hex.encode()
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if full_pattern in key and key[-1:] == b'o':
                return cf_name, key, bytes(it.value())
            it.next()
    return None


def fetch_shards(db, cf_name, onode_key: bytes, shard_offsets: list[int]) -> list[dict]:
    """Spanning shard 들을 fetch."""
    cf = db.get_column_family(cf_name)
    out = []
    for soff in shard_offsets:
        skey = onode_key + struct.pack(">I", soff) + b"x"
        sval = cf.get(skey)
        if sval is None:
            out.append({"shard_offset": soff, "error": "not found"})
        else:
            sval_bytes = bytes(sval)
            parsed = parse_shard(sval_bytes)
            parsed["shard_offset"] = soff
            parsed["raw_value"] = sval_bytes
            out.append(parsed)
    return out


def read_disk_bytes(raw_path: Path, lv_offset: int, length: int) -> bytes:
    """LV-relative offset → raw 디스크 byte 읽기. PE start = 0x100000 (PV-FULL-DUMP)."""
    pv_offset = lv_offset + PV_LV_OFFSET   # PV_LV_OFFSET = 0x100000 from step_d
    with open(raw_path, "rb") as f:
        f.seek(pv_offset)
        return f.read(length)


def assemble_chunk(shards: list[dict], raw_path: Path) -> tuple[bytes, list[dict]]:
    """11 shards 의 extent 들 → logical 4 MiB 영역으로 조립.
       chunk 안 logical_offset (0 ~ 4 MiB) 에 pextent.offset 의 디스크 byte 매핑.
    """
    chunk_size = 4 * 1024 * 1024
    out = bytearray(chunk_size)
    extent_log = []
    for shard in shards:
        if "extents" not in shard:
            continue
        for ext in shard["extents"]:
            if "blob" not in ext:
                continue
            blob = ext["blob"]
            blob_off = ext["blob_offset"]
            length = ext["length"]
            log_off = ext["logical_offset"]
            # blob 의 pextents 안에서 blob_off byte 위치 찾기 (blob 안 logical 위치)
            cum = 0
            extracted = bytearray()
            remaining = length
            for pe in blob["extents"]:
                pe_len = pe["length"]
                if cum + pe_len <= blob_off:
                    cum += pe_len
                    continue
                # 시작 위치
                rel = blob_off - cum if cum < blob_off else 0
                start_in_pe = pe["offset"] + rel
                avail = pe_len - rel
                take = min(avail, remaining)
                disk_bytes = read_disk_bytes(raw_path, start_in_pe, take)
                extracted += disk_bytes
                remaining -= take
                cum += pe_len
                if remaining <= 0:
                    break
            # logical 위치에 복사
            if log_off + length <= chunk_size:
                out[log_off:log_off+length] = extracted
            extent_log.append({
                "shard_offset": shard["shard_offset"],
                "logical_offset": log_off,
                "blob_offset": blob_off,
                "length": length,
                "extracted_len": len(extracted),
                "blob_pextents": [{"offset": p["offset"], "length": p["length"]} for p in blob["extents"]],
                "blob_flags": blob.get("flags", 0),
                "blob_csum_type": blob.get("csum_type"),
            })
    return bytes(out), extent_log


def main():
    print("=" * 100)
    print("단계 H — chunk 시범 추출 + 검증")
    print("=" * 100)

    OUT_DIR = EXTRACTED_BASE / "_h_results"
    OUT_DIR.mkdir(exist_ok=True)

    chunk_data_per_osd = {}
    decoded_per_osd = {}

    for osd in ["osd.1", "osd.2"]:   # vm-104 가 SST 에 있는 OSD 들
        print(f"\n{'─' * 100}")
        print(f"  {osd}")
        print(f"{'─' * 100}")
        db_dir = EXTRACTED_BASE / osd / "db"
        db, cf_list = open_readonly(db_dir)
        hit = find_chunk_onode(db, cf_list, TARGET_PATTERN, TARGET_CHUNK_HEX)
        if hit is None:
            print(f"  chunk onode NOT FOUND")
            db.close()
            continue
        cf_name, onode_key, onode_value = hit
        print(f"  cf={cf_name}  key_len={len(onode_key)}  value_len={len(onode_value)}")

        # H-1: onode parse
        from step_h1_dump_chunk_onode import parse_onode
        on = parse_onode(onode_value)
        print(f"  onode: nid={on['nid']}, size={on['size']}, n_shards={on['n_shards']}")

        # H-2: object_info_t
        oi_ptr = on["attrs"][b"_"]
        oi = parse_object_info(oi_ptr)
        print(f"\n  object_info_t:")
        print(f"    struct_v/c/len:     {oi.get('struct_v')}/{oi.get('struct_compat')}/{oi.get('struct_len')}")
        print(f"    size:               {oi.get('size')}")
        if "mtime" in oi:
            print(f"    mtime:              {oi['mtime']['sec']}.{oi['mtime']['nsec']:09d}")
        print(f"    flags:              0x{oi.get('flags', 0):08x}  {oi.get('flag_names', [])}")
        print(f"    data_digest:        0x{oi.get('data_digest', 0):08x}")
        print(f"    omap_digest:        0x{oi.get('omap_digest', 0):08x}")
        print(f"    expected_obj_size:  {oi.get('expected_object_size')}")
        print(f"    body_remaining:     {oi.get('body_remaining', 0)}")
        if "error" in oi:
            print(f"    ERROR: {oi['error']}")

        # H-3: shards
        shard_offsets = [s["offset"] for s in on["extent_map_shards"]]
        shards = fetch_shards(db, cf_name, onode_key, shard_offsets)
        print(f"\n  shards parsed: {len(shards)}")
        for i, s in enumerate(shards):
            if "error" in s:
                print(f"    [{i}] offset=0x{s.get('shard_offset', 0):x}: ERROR {s['error']}")
                continue
            print(f"    [{i}] offset=0x{s['shard_offset']:>6x}  v={s.get('struct_v')}  "
                  f"n_extents={s.get('n_extents')}  local_blobs={s.get('local_blobs_count')}  "
                  f"consumed={s.get('bytes_consumed')}/{s.get('raw_len')}  "
                  f"remaining={s.get('bytes_remaining')}")
            if "error" in s:
                print(f"        SHARD ERROR: {s['error']}")
            for j, ext in enumerate(s.get("extents", [])):
                if "blob" not in ext:
                    print(f"        ext[{j}] log=0x{ext['logical_offset']:x} len=0x{ext['length']:x}  blob=?  spanning={ext['spanning']} idx={ext['blob_idx']}")
                    continue
                pe_str = ", ".join(f"(d=0x{p['offset']:x}+0x{p['length']:x})" for p in ext['blob']['extents'])
                csum_t = ext['blob'].get('csum_type', '?')
                print(f"        ext[{j}] log=0x{ext['logical_offset']:>6x} blob_off=0x{ext['blob_offset']:x} len=0x{ext['length']:x}  pextents=[{pe_str}]  csum_t={csum_t}")

        # H-4: assemble + verify
        raw_path = OSD_RAW[osd]
        print(f"\n  reading from raw: {raw_path}")
        chunk_bytes, extent_log = assemble_chunk(shards, raw_path)
        sha256 = hashlib.sha256(chunk_bytes).hexdigest()
        non_zero = sum(1 for b in chunk_bytes if b != 0)
        print(f"  chunk extracted: {len(chunk_bytes)} byte, SHA-256 = {sha256}")
        print(f"  non-zero byte count: {non_zero}/{len(chunk_bytes)} ({100*non_zero/len(chunk_bytes):.1f}%)")

        # 저장
        out_bin = OUT_DIR / f"{osd}_vm104_chunk_{TARGET_CHUNK_HEX}.bin"
        with open(out_bin, "wb") as f:
            f.write(chunk_bytes)
        print(f"  saved: {out_bin.name}")

        chunk_data_per_osd[osd] = chunk_bytes
        decoded_per_osd[osd] = {
            "data_digest_oi": oi.get("data_digest"),
            "size_oi": oi.get("size"),
            "sha256": sha256,
        }
        db.close()

    # R4 cross-OSD 비교
    print(f"\n{'━' * 100}")
    print("R4 cross-OSD byte-identical 검증")
    print(f"{'━' * 100}")
    if "osd.1" in chunk_data_per_osd and "osd.2" in chunk_data_per_osd:
        b1 = chunk_data_per_osd["osd.1"]
        b2 = chunk_data_per_osd["osd.2"]
        match = b1 == b2
        print(f"  byte-identical: {'✓ R4 PASS' if match else '✗ MISMATCH'}")
        if not match:
            diff_pos = [i for i in range(min(len(b1), len(b2))) if b1[i] != b2[i]]
            print(f"  diff positions: {len(diff_pos)} (first 10: {diff_pos[:10]})")
        sha1 = decoded_per_osd["osd.1"]["sha256"]
        sha2 = decoded_per_osd["osd.2"]["sha256"]
        print(f"  osd.1 SHA-256: {sha1}")
        print(f"  osd.2 SHA-256: {sha2}")
        print(f"  data_digest osd.1: 0x{decoded_per_osd['osd.1']['data_digest_oi']:08x}")
        print(f"  data_digest osd.2: 0x{decoded_per_osd['osd.2']['data_digest_oi']:08x}")

    # CRC32C verify (data_digest)
    print(f"\n{'━' * 100}")
    print("CRC32C(chunk_bytes) vs object_info.data_digest 검증")
    print(f"{'━' * 100}")
    # Ceph 의 data_digest 는 표준 crc32c (init=-1, finalXOR=-1)
    if "osd.1" in chunk_data_per_osd:
        from step_e5_wal_parser import crc32c as crc32c_std
        crc = crc32c_std(chunk_data_per_osd["osd.1"])
        dd = decoded_per_osd["osd.1"]["data_digest_oi"]
        print(f"  computed CRC32C standard: 0x{crc:08x}")
        print(f"  data_digest from oi:      0x{dd:08x}")
        print(f"  match: {'✓' if crc == dd else '✗'}")


if __name__ == "__main__":
    main()
