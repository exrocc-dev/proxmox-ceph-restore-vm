"""
단계 D — BlueFS superblock decode + transaction log replay

목적: BlueFS super (LV offset 0x1000 = PV offset 0x101000) 부터 시작해서
      transaction log 를 끝까지 replay → RocksDB 파일들 (.sst·.log·CURRENT·
      MANIFEST-*) 의 fnode (extents 포함) 확보.

R8: read-only.
근거 spec (verbatim): 06.md §2.1~2.6 / §3.1~3.6
  - bluefs_types.h v18.2.8 (struct definitions)
  - bluefs_types.cc::bluefs_super_t::encode / bluefs_transaction_t::encode
  - denc.h v18.2.8 (denc_varint, denc_varint_lowz, denc_lba)
  - BlueFS.h v18.2.8 (get_super_offset() = 4096)

검증 oracle:
  - super.osd_uuid == 단계 B 의 label.osd_uuid (raw에서 추출한 것끼리 비교)
  - super CRC32C 일치
  - 채택 transaction 의 (CRC32C 일치) AND (uuid == super.uuid) AND (seq 단조 증가)
  - 결과 file_map 에 RocksDB 표준 파일들 (CURRENT/MANIFEST-*/*.sst/*.log) 존재
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from _dataset_path import RAW_DIR as OSD3_DIR, OSD_RAW

# ---------- 환경 ----------
# RAWS: dataset 안 pveX.001 자동 인식
RAWS = sorted([p.name for p in OSD_RAW.values()],
              key=lambda n: int(n.replace("pve","").replace(".001","") or "1")) \
       if OSD_RAW else ["pve.001", "pve2.001", "pve3.001"]
PV_LV_OFFSET = 0x100000
SUPER_OFFSET_LV = 0x1000
SUPER_BLOCK_SIZE = 4096

# 단계 B 결과 (raw 추출값) — D 의 self-cross-verify 용
LABEL_OSD_UUID = {
    "pve.001":  "148b3d2d-cf76-4169-86de-e4da033b431c",
    "pve2.001": "79b096d6-a01c-44f4-b610-23dee92ade00",
    "pve3.001": "5b851eca-5f0a-4403-8765-d6ca835e92dc",
}


# ---------- CRC32C (Castagnoli) software 구현 ----------
# polynomial: 0x1EDC6F41, reversed: 0x82F63B78
# Ceph 변형: init = 0xFFFFFFFF (= -1), **finalXOR 미적용** (raw register value)
# 첫 시도에서 stored XOR computed == 0xFFFFFFFF 패턴 관찰 → finalXOR 빼야 함
# (standard CRC32C 는 finalXOR 0xFFFFFFFF 적용. Ceph 는 raw 저장.)
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes, init: int = 0xFFFFFFFF) -> int:
    """Ceph variant: init=-1, no final XOR."""
    crc = init & 0xFFFFFFFF
    for b in data:
        crc = ((crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]) & 0xFFFFFFFF
    return crc


# ---------- DENC primitives (06.md §3) ----------
def read_u8(buf, off):  return buf[off], off + 1
def read_u16_le(buf, off):  return int.from_bytes(buf[off:off+2], "little"), off + 2
def read_u32_le(buf, off):  return int.from_bytes(buf[off:off+4], "little"), off + 4
def read_u64_le(buf, off):  return int.from_bytes(buf[off:off+8], "little"), off + 8


def read_denc_header(buf, off):
    """6 byte: u8 v + u8 compat + u32_le struct_len."""
    sv = buf[off]
    cv = buf[off + 1]
    sl = int.from_bytes(buf[off + 2:off + 6], "little")
    return (sv, cv, sl), off + 6


def read_denc_varint(buf, off):
    """LEB128 unsigned."""
    val, shift = 0, 0
    while True:
        b = buf[off]; off += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, off


def read_denc_varint_lowz(buf, off):
    """varint with low-zero nibble compression: low 2 bits = nibble count."""
    val, off = read_denc_varint(buf, off)
    lowznib = val & 0x3
    val >>= 2
    val <<= (lowznib * 4)
    return val, off


def read_denc_lba(buf, off):
    """LBA encoding (06.md §3.5):
       first 4-byte ceph_le32 with mode in low bits, optional varint tail when bit 31 set.
    """
    word = int.from_bytes(buf[off:off + 4], "little")
    off += 4

    # mode by low bit pattern (4 distinct prefixes)
    if (word & 0x1) == 0x0:           # mode 0: 12 bit zero compression, data in bits 1..30
        v = (word & 0x7FFFFFFE) << (12 - 1)
        shift = 12 + 30
    elif (word & 0x3) == 0x1:         # mode 1: 16 bit zero, data in bits 2..30
        v = (word & 0x7FFFFFFC) << (16 - 2)
        shift = 16 + 29
    elif (word & 0x7) == 0x3:         # mode 3: 20 bit zero, data in bits 3..30
        v = (word & 0x7FFFFFF8) << (20 - 3)
        shift = 20 + 28
    else:                              # mode 7: byte-aligned, data in bits 3..30
        v = (word & 0x7FFFFFF8) >> 3
        shift = 28

    if word & 0x80000000:              # continuation flag
        tail, off = read_denc_varint(buf, off)
        v |= tail << shift
    return v, off


def read_string_u32(buf, off):
    """std::string encoded as u32_le len + raw bytes (no NUL)."""
    n, off = read_u32_le(buf, off)
    return buf[off:off + n].decode("utf-8", errors="replace"), off + n


def read_uuid_raw(buf, off):
    raw = buf[off:off + 16]
    h = raw.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}", off + 16


# ---------- BlueFS structures ----------
def read_bluefs_extent(buf, off):
    """DENC_START(1,1) + denc_lba(offset) + denc_varint_lowz(length) + u8(bdev)."""
    (sv, cv, sl), header_end = read_denc_header(buf, off)
    body_end = header_end + sl
    p = header_end
    ext_off, p = read_denc_lba(buf, p)
    length, p = read_denc_varint_lowz(buf, p)
    bdev = buf[p]; p += 1
    return {"offset": ext_off, "length": length, "bdev": bdev, "sv": sv, "cv": cv}, body_end


def read_bluefs_fnode(buf, off):
    """DENC_START(1,1) + varint(ino) + varint(size) + utime(8) + u8(unused) + vector<extent>.
       vector encoded as u32_le count + count * extent.
    """
    (sv, cv, sl), header_end = read_denc_header(buf, off)
    body_end = header_end + sl
    p = header_end
    ino, p = read_denc_varint(buf, p)
    size, p = read_denc_varint(buf, p)
    mtime_sec, p = read_u32_le(buf, p)
    mtime_nsec, p = read_u32_le(buf, p)
    unused = buf[p]; p += 1
    n_ext, p = read_u32_le(buf, p)
    extents = []
    for _ in range(n_ext):
        ext, p = read_bluefs_extent(buf, p)
        extents.append(ext)
    return {
        "ino": ino, "size": size,
        "mtime_sec": mtime_sec, "mtime_nsec": mtime_nsec,
        "unused": unused, "extents": extents,
        "sv": sv, "cv": cv,
    }, body_end


def read_bluefs_fnode_delta(buf, off):
    """bluefs_fnode_delta_t (Pacific+, 06.md §10.7 보강):
       DENC_START(1,1) + denc_varint(ino) + denc_varint(size_delta)
                       + utime mtime (8 byte) + u64_le offset
                       + vector<bluefs_extent_t> extents (u32 count + extents)
       offset == fnode.allocated 이면 append 모드, 그렇지 않으면 overlay.
    """
    (sv, cv, sl), header_end = read_denc_header(buf, off)
    body_end = header_end + sl
    p = header_end
    ino, p = read_denc_varint(buf, p)
    size_delta, p = read_denc_varint(buf, p)
    mtime_sec, p = read_u32_le(buf, p)
    mtime_nsec, p = read_u32_le(buf, p)
    offset, p = read_u64_le(buf, p)
    n_ext, p = read_u32_le(buf, p)
    extents = []
    for _ in range(n_ext):
        ext, p = read_bluefs_extent(buf, p)
        extents.append(ext)
    return {
        "ino": ino, "size_delta": size_delta,
        "mtime_sec": mtime_sec, "mtime_nsec": mtime_nsec,
        "offset": offset, "extents": extents,
    }, body_end


def read_bluefs_layout(buf, off):
    """DENC_START(1,1) + u32 shared_bdev + u8 dedicated_db + u8 dedicated_wal."""
    (sv, cv, sl), header_end = read_denc_header(buf, off)
    body_end = header_end + sl
    p = header_end
    shared_bdev, p = read_u32_le(buf, p)
    dedicated_db = buf[p]; p += 1
    dedicated_wal = buf[p]; p += 1
    return {
        "shared_bdev": shared_bdev,
        "dedicated_db": bool(dedicated_db),
        "dedicated_wal": bool(dedicated_wal),
    }, body_end


def decode_super(block: bytes) -> dict:
    """ENCODE_START(2,1) + uuid(16) + osd_uuid(16) + u64 version + u32 block_size
       + bluefs_fnode_t log_fnode + std::optional<bluefs_layout_t>.
       After body: 4 byte CRC32C of bytes [0 .. body_end).
    """
    (sv, cv, sl), header_end = read_denc_header(block, 0)
    body_end = header_end + sl
    p = header_end
    uuid, p = read_uuid_raw(block, p)
    osd_uuid, p = read_uuid_raw(block, p)
    version, p = read_u64_le(block, p)
    block_size, p = read_u32_le(block, p)
    log_fnode, p = read_bluefs_fnode(block, p)

    layout = None
    if sv >= 2 and p < body_end:
        present = block[p]; p += 1
        if present:
            layout, p = read_bluefs_layout(block, p)

    crc_stored = int.from_bytes(block[body_end:body_end + 4], "little")
    crc_computed = crc32c(block[:body_end])

    return {
        "struct_v": sv, "struct_compat": cv, "struct_len": sl,
        "uuid": uuid, "osd_uuid": osd_uuid,
        "version": version, "block_size": block_size,
        "log_fnode": log_fnode, "memorized_layout": layout,
        "crc_stored": crc_stored, "crc_computed": crc_computed,
        "crc_ok": crc_stored == crc_computed,
        "body_end": body_end,
        "body_consumed": p,
    }


# ---------- transaction replay ----------
OP_NAMES = {
    0: "OP_NONE", 1: "OP_INIT", 2: "OP_ALLOC_ADD(legacy)", 3: "OP_ALLOC_RM(legacy)",
    4: "OP_DIR_LINK", 5: "OP_DIR_UNLINK", 6: "OP_DIR_CREATE", 7: "OP_DIR_REMOVE",
    8: "OP_FILE_UPDATE", 9: "OP_FILE_REMOVE", 10: "OP_JUMP", 11: "OP_JUMP_SEQ",
    12: "OP_FILE_UPDATE_INC",
}


def parse_ops(op_bl: bytes):
    """Parse op_bl into list of (op_name, payload_dict). Returns (ops, ok)."""
    ops = []
    p = 0
    n = len(op_bl)
    while p < n:
        opc = op_bl[p]; p += 1
        try:
            if opc == 1:    # OP_INIT
                ops.append(("OP_INIT", {}))
            elif opc == 6:  # OP_DIR_CREATE
                d, p = read_string_u32(op_bl, p)
                ops.append(("OP_DIR_CREATE", {"dir": d}))
            elif opc == 7:  # OP_DIR_REMOVE
                d, p = read_string_u32(op_bl, p)
                ops.append(("OP_DIR_REMOVE", {"dir": d}))
            elif opc == 4:  # OP_DIR_LINK
                d, p = read_string_u32(op_bl, p)
                f, p = read_string_u32(op_bl, p)
                ino, p = read_u64_le(op_bl, p)
                ops.append(("OP_DIR_LINK", {"dir": d, "file": f, "ino": ino}))
            elif opc == 5:  # OP_DIR_UNLINK
                d, p = read_string_u32(op_bl, p)
                f, p = read_string_u32(op_bl, p)
                ops.append(("OP_DIR_UNLINK", {"dir": d, "file": f}))
            elif opc == 8:  # OP_FILE_UPDATE
                fnode, p = read_bluefs_fnode(op_bl, p)
                ops.append(("OP_FILE_UPDATE", {"fnode": fnode}))
            elif opc == 9:  # OP_FILE_REMOVE
                ino, p = read_u64_le(op_bl, p)
                ops.append(("OP_FILE_REMOVE", {"ino": ino}))
            elif opc == 10: # OP_JUMP
                next_seq, p = read_u64_le(op_bl, p)
                offset, p = read_u64_le(op_bl, p)
                ops.append(("OP_JUMP", {"next_seq": next_seq, "offset": offset}))
            elif opc == 11: # OP_JUMP_SEQ
                next_seq, p = read_u64_le(op_bl, p)
                ops.append(("OP_JUMP_SEQ", {"next_seq": next_seq}))
            elif opc == 12: # OP_FILE_UPDATE_INC (Pacific+)
                delta, p = read_bluefs_fnode_delta(op_bl, p)
                ops.append(("OP_FILE_UPDATE_INC", {"delta": delta}))
            elif opc in (2, 3):  # legacy alloc — pre-Pacific only
                # 우리 OSD 는 Reef 18.2.8 (Pacific+) 이라 일반적으로 미발생
                # 단 발생 시 spec: u8 bdev + u64 offset + u64 length 가정
                bdev = op_bl[p]; p += 1
                offset, p = read_u64_le(op_bl, p)
                length, p = read_u64_le(op_bl, p)
                ops.append((OP_NAMES[opc], {"bdev": bdev, "offset": offset, "length": length}))
            else:
                # 알 수 없는 op — 정직하게 abort
                return ops, False, f"unknown op_code 0x{opc:02x} at op_bl pos {p-1}"
        except (IndexError, UnicodeDecodeError) as e:
            return ops, False, f"op decode error at pos {p}: {e}"
    return ops, True, None


def decode_transaction(buf, off, super_uuid):
    """Try to decode one transaction at buf[off:]. Returns (tx_dict, next_off) or (None, off).
       Adoption checks: per-tx CRC32C + uuid == super.uuid (caller checks seq monotonic).
    """
    if off + 6 > len(buf):
        return None, off, "buffer too short for header"
    try:
        (sv, cv, sl), header_end = read_denc_header(buf, off)
    except IndexError:
        return None, off, "header read error"
    if not (sv == 1 and cv == 1):
        return None, off, f"bad version v={sv} c={cv}"
    body_end = header_end + sl
    if body_end + 4 > len(buf):
        return None, off, "body+CRC overflow"

    p = header_end
    try:
        uuid, p = read_uuid_raw(buf, p)
        seq, p = read_u64_le(buf, p)
        op_bl_len, p = read_u32_le(buf, p)
    except IndexError:
        return None, off, "tx body read error"

    op_bl_start = p
    op_bl_end = op_bl_start + op_bl_len
    if op_bl_end + 4 > body_end + 4:    # +4 for the CRC
        return None, off, "op_bl overflow body"
    op_bl = buf[op_bl_start:op_bl_end]
    crc_stored = int.from_bytes(buf[op_bl_end:op_bl_end + 4], "little")
    crc_computed = crc32c(op_bl)

    if uuid != super_uuid:
        return None, off, f"uuid mismatch (tx={uuid} super={super_uuid})"
    if crc_computed != crc_stored:
        return None, off, f"CRC32C mismatch (computed=0x{crc_computed:08x} stored=0x{crc_stored:08x})"

    # body_end may differ from op_bl_end+4 if forward-compat padding present
    # The encoded transaction's total span = header_end + sl
    return {
        "uuid": uuid, "seq": seq,
        "op_bl_len": op_bl_len, "op_bl": op_bl,
        "crc": crc_stored,
    }, body_end, None


def read_extents_bytes(raw_path: Path, extents: list) -> bytes:
    """주어진 extents 의 byte 들을 concatenate."""
    parts = []
    with open(raw_path, "rb") as f:
        for ext in extents:
            f.seek(PV_LV_OFFSET + ext["offset"])
            parts.append(f.read(ext["length"]))
    return b"".join(parts)


def assemble_journal(raw_path: Path, log_fnode: dict) -> bytes:
    """legacy alias — log_fnode.extents 따라 journal byte stream 조립."""
    return read_extents_bytes(raw_path, log_fnode["extents"])


def replay(raw_path: Path, super_info: dict):
    """Apply transactions, with dynamic log extension via OP_FILE_UPDATE_INC for ino=1.

    BlueFS log 가 자라면 OP_FILE_UPDATE_INC for ino=1 가 새 extents 를 append.
    이 경우 우리 journal byte stream 도 동적으로 확장해서 그 안의 transaction 까지 read.
    """
    # ino=1 (log) 의 fnode 는 super.log_fnode 에서 시작 — 동적으로 확장됨
    log_fnode = {
        "ino": 1, "size": super_info["log_fnode"]["size"],
        "mtime_sec": super_info["log_fnode"]["mtime_sec"],
        "mtime_nsec": super_info["log_fnode"]["mtime_nsec"],
        "unused": super_info["log_fnode"]["unused"],
        "extents": list(super_info["log_fnode"]["extents"]),
    }
    file_map = {1: log_fnode}
    dir_map = {}

    journal = read_extents_bytes(raw_path, log_fnode["extents"])
    last_seq = 0
    pos = 0
    accepted = 0
    rejected_reason = None
    ops_total = 0
    ops_by_type = {}
    extensions = 0

    MAX_TX = 200000
    while pos < len(journal) and accepted < MAX_TX:
        tx, next_pos, reason = decode_transaction(journal, pos, super_info["uuid"])
        if tx is None:
            rejected_reason = reason
            break
        if tx["seq"] <= last_seq:
            rejected_reason = f"non-monotonic seq ({tx['seq']} <= {last_seq})"
            break
        last_seq = tx["seq"]
        accepted += 1

        ops, ok, err = parse_ops(tx["op_bl"])
        ops_total += len(ops)

        log_extended = False
        jump_to = None

        for op_name, op_data in ops:
            ops_by_type[op_name] = ops_by_type.get(op_name, 0) + 1
            if op_name == "OP_DIR_CREATE":
                dir_map.setdefault(op_data["dir"], {})
            elif op_name == "OP_DIR_REMOVE":
                dir_map.pop(op_data["dir"], None)
            elif op_name == "OP_DIR_LINK":
                dir_map.setdefault(op_data["dir"], {})[op_data["file"]] = op_data["ino"]
            elif op_name == "OP_DIR_UNLINK":
                d = dir_map.get(op_data["dir"])
                if d is not None:
                    d.pop(op_data["file"], None)
            elif op_name == "OP_FILE_UPDATE":
                fn = op_data["fnode"]
                file_map[fn["ino"]] = fn
            elif op_name == "OP_FILE_REMOVE":
                file_map.pop(op_data["ino"], None)
            elif op_name == "OP_FILE_UPDATE_INC":
                delta = op_data["delta"]
                target = file_map.get(delta["ino"])
                if target is None:
                    # delta target 미존재 — 일단 새 fnode 처럼 처리
                    target = {
                        "ino": delta["ino"], "size": 0,
                        "mtime_sec": delta["mtime_sec"], "mtime_nsec": delta["mtime_nsec"],
                        "unused": 0, "extents": [],
                    }
                    file_map[delta["ino"]] = target
                allocated = sum(e["length"] for e in target["extents"])
                if delta["offset"] == allocated:
                    # APPEND 모드
                    target["extents"].extend(delta["extents"])
                else:
                    # OVERLAY — 단순 구현: offset 위치부터 새 extents 로 교체
                    # (full overlay spec 미보강 — Phase 5 보강 가능)
                    cum = 0
                    new_ex = []
                    for e in target["extents"]:
                        if cum + e["length"] <= delta["offset"]:
                            new_ex.append(e)
                            cum += e["length"]
                        else:
                            break
                    new_ex.extend(delta["extents"])
                    target["extents"] = new_ex
                # delta["size_delta"] is misnamed — it is the NEW logical size of the file,
                # not a delta. Ceph BlueFS::OP_FILE_UPDATE_INC writes fnode.size verbatim.
                # 이전 도구 (osd3) 는 4 MiB allocation 까지 안 채워서 우연히 정확.
                # 4 MiB allocation 가득 찬 case (osd5 MANIFEST) 는 allocated == logical 처럼 보여 silent corrupt.
                target["size"] = delta["size_delta"]
                target["mtime_sec"] = delta["mtime_sec"]
                target["mtime_nsec"] = delta["mtime_nsec"]
                # ino==1 (log 자체) 면 journal byte stream 확장
                if delta["ino"] == 1:
                    log_extended = True
            elif op_name == "OP_JUMP":
                last_seq = op_data["next_seq"] - 1
                jump_to = op_data["offset"]   # log file 내 byte offset 으로 이동
            elif op_name == "OP_JUMP_SEQ":
                last_seq = op_data["next_seq"] - 1

        if not ok:
            rejected_reason = f"op parse error: {err}"
            break

        # OP_JUMP 가 있었으면 그 offset 으로 jump, 아니면 다음 tx 위치
        pos = jump_to if jump_to is not None else next_pos

        # log_fnode 가 변경됐으면 journal byte stream 재조립
        if log_extended:
            extensions += 1
            new_journal = read_extents_bytes(raw_path, file_map[1]["extents"])
            if len(new_journal) > len(journal):
                journal = new_journal

        # BlueFS 는 transaction 을 block_size (4 KiB) 단위로 align 해서 작성.
        # 현재 위치에서 decode 가 안 되면 (zero padding), 다음 block 경계로 advance
        # 후 valid tx 가 있는지 retry. 이게 R8 정석 (CRC + uuid + seq 검증으로 false-positive 0).
        bs = super_info["block_size"]
        if pos < len(journal):
            # peek — 현재 위치에서 decode 가능한지
            peek_tx, _, _ = decode_transaction(journal, pos, super_info["uuid"])
            if peek_tx is None or peek_tx["seq"] <= last_seq:
                # 다음 block 경계로 advance
                next_block = ((pos // bs) + 1) * bs
                while next_block < len(journal):
                    peek2, _, _ = decode_transaction(journal, next_block, super_info["uuid"])
                    if peek2 is not None and peek2["seq"] > last_seq:
                        pos = next_block
                        break
                    next_block += bs
                else:
                    break  # journal 끝까지 valid tx 못 찾음

    return {
        "file_map": file_map, "dir_map": dir_map,
        "accepted": accepted, "last_seq": last_seq,
        "ops_total": ops_total, "ops_by_type": ops_by_type,
        "stop_pos": pos, "stop_reason": rejected_reason,
        "journal_size": len(journal),
        "log_extensions": extensions,
        "log_extents_final": file_map[1]["extents"],
    }


# ---------- main ----------
def main():
    print("=" * 80)
    print("단계 D — BlueFS super decode + transaction log replay")
    print(f"Super position: PV-relative 0x{PV_LV_OFFSET + SUPER_OFFSET_LV:x}")
    print("=" * 80)

    self_check_pass = 0
    self_check_total = 0

    for raw_name in RAWS:
        path = OSD3_DIR / raw_name
        with open(path, "rb") as f:
            f.seek(PV_LV_OFFSET + SUPER_OFFSET_LV)
            block = f.read(SUPER_BLOCK_SIZE)

        try:
            super_info = decode_super(block)
        except Exception as e:
            print(f"\n{raw_name}: SUPER DECODE FAILED — {type(e).__name__}: {e}")
            continue

        print(f"\n{'─' * 80}")
        print(f"{raw_name}")
        print(f"{'─' * 80}")
        print(f"  super DENC:        v={super_info['struct_v']} c={super_info['struct_compat']} len={super_info['struct_len']}")
        print(f"  super uuid:        {super_info['uuid']}")
        print(f"  super osd_uuid:    {super_info['osd_uuid']}")

        # SELF-CROSS-VERIFY 1: super.osd_uuid == 단계 B 의 label.osd_uuid
        # dataset 별 UUID 가 dict 에 없으면 verify skip (osd3 hard-coded → osd4/osd5 등)
        if raw_name in LABEL_OSD_UUID:
            self_check_total += 1
            match = super_info['osd_uuid'] == LABEL_OSD_UUID[raw_name]
            if match:
                self_check_pass += 1
            print(f"     == label.osd_uuid: {'✓' if match else '✗'}")
        else:
            print(f"     == label.osd_uuid: (no UUID in osd3 reference dict — verify skip)")

        # SELF-CROSS-VERIFY 2: super CRC32C
        self_check_total += 1
        if super_info['crc_ok']:
            self_check_pass += 1
        print(f"  super CRC32C:      stored=0x{super_info['crc_stored']:08x} computed=0x{super_info['crc_computed']:08x} {'✓' if super_info['crc_ok'] else '✗'}")

        print(f"  version:           {super_info['version']}")
        print(f"  block_size:        0x{super_info['block_size']:x} ({super_info['block_size']:,} byte)")
        if super_info["memorized_layout"]:
            ml = super_info["memorized_layout"]
            print(f"  layout:            shared_bdev={ml['shared_bdev']} ded_db={ml['dedicated_db']} ded_wal={ml['dedicated_wal']}")
        else:
            print(f"  layout:            (none)")

        log_fn = super_info['log_fnode']
        print(f"  log_fnode:         ino={log_fn['ino']}  size={log_fn['size']:,}  extents={len(log_fn['extents'])}")
        for i, ext in enumerate(log_fn['extents'][:8]):
            print(f"    [{i}] bdev={ext['bdev']}  offset=0x{ext['offset']:09x}  length=0x{ext['length']:x} ({ext['length']:,})")
        if len(log_fn['extents']) > 8:
            print(f"    ... and {len(log_fn['extents']) - 8} more")

        # Replay (with dynamic log extension)
        result = replay(path, super_info)

        print(f"\n  REPLAY RESULTS")
        print(f"    journal byte:    {result['journal_size']:,} (initial 64K + {result['log_extensions']} extension(s))")
        print(f"    txs accepted:    {result['accepted']}")
        print(f"    last seq:        {result['last_seq']}")
        print(f"    ops total:       {result['ops_total']}")
        print(f"    stop reason:     {result['stop_reason']}")
        print(f"    stop position:   {result['stop_pos']:,} of {result['journal_size']:,} ({100*result['stop_pos']/result['journal_size']:.1f}%)")
        print(f"    final log extents ({len(result['log_extents_final'])}):")
        for i, ext in enumerate(result['log_extents_final'][:6]):
            print(f"      [{i}] bdev={ext['bdev']} offset=0x{ext['offset']:09x} length=0x{ext['length']:x}")
        if len(result['log_extents_final']) > 6:
            print(f"      ... +{len(result['log_extents_final']) - 6} more")

        if result["ops_by_type"]:
            print(f"    op type counts:")
            for op_name in sorted(result["ops_by_type"]):
                print(f"      {op_name:<25s} {result['ops_by_type'][op_name]:>6d}")

        fm = result["file_map"]
        dm = result["dir_map"]
        print(f"\n  FILE_MAP  ({len(fm)} files)")
        for ino in sorted(fm):
            fn = fm[ino]
            print(f"    ino={ino:5d}  size={fn['size']:>12,}  extents={len(fn['extents'])}")

        print(f"\n  DIR_MAP  ({len(dm)} dirs)")
        for dirname in sorted(dm):
            files = dm[dirname]
            print(f"    {dirname}/  ({len(files)} files)")
            for fname in sorted(files):
                ino = files[fname]
                sz = fm[ino]['size'] if ino in fm else "?"
                print(f"      {fname:<32s} ino={ino:5d}  size={sz}")

    print(f"\n{'=' * 80}")
    print(f"SELF-CROSS-VERIFY summary: {self_check_pass}/{self_check_total}  "
          f"({'✓ ALL PASS' if self_check_pass == self_check_total else '✗ SOME FAILED'})")
    print('=' * 80)


if __name__ == "__main__":
    main()
