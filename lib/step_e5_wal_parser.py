"""
단계 E-5 — RocksDB WAL 직접 파서 (사용자 옵션 1, R8 정석)

목적: db.wal/*.log 의 byte 를 직접 파싱해서 PUT/DEL/SDEL/DELRANGE op 들을
      sequence number 순으로 추출. SST snapshot 과 별개 timeline 으로 분리.

사용자 지시 4 항목:
  #2 PUT/DELETE 모두 추출 (DELETE 도 forensic 가치)
     같은 key 의 multiple PUT 기록 (중간 state 도 의미)
     sequence number 보존
     SST 와 별개 timeline
  #3 SST = 과거 state, WAL = 최근 transaction
  #4 R3 가설 재검증 — 옛 vm-100 (ff183be962b56) 의 DELETE 가 WAL 안 있는지

RocksDB WAL format spec (RocksDB 7.x+, Ceph Reef 18.2.8):
  - 32 KiB block 단위
  - Record:
    legacy:     [u32 LE crc] [u16 LE len] [u8 type=1/2/3/4]                    [payload]
    recyclable: [u32 LE crc] [u16 LE len] [u8 type=5/6/7/8] [u32 LE log_num]  [payload]
  - CRC = Mask(crc32c(type [+ log_num] + payload))
    Mask(crc) = ((crc >> 15) | (crc << 17)) + 0xa282ead8
    crc32c = standard (final XOR ^ 0xFFFFFFFF, 단계 D 의 Ceph variant 와 다름)
  - Type: 1/5=Full, 2/6=First, 3/7=Middle, 4/8=Last, 0=Padding
  - Payload (assembled) = WriteBatch:
      [u64 LE seq] [u32 LE count] [op records...]
  - Op record types (BlueStore 가 주로 사용하는 것):
      0  Deletion default CF       [u8=0][varint klen][key]
      1  Value default CF          [u8=1][varint klen][key][varint vlen][value]
      4  CF Deletion               [u8=4][varint cf_id][varint klen][key]
      5  CF Value                  [u8=5][varint cf_id][varint klen][key][varint vlen][value]
      7  SingleDeletion default    [u8=7][varint klen][key]
      8  CF SingleDeletion         [u8=8][varint cf_id][varint klen][key]
     13  Noop                       [u8=13]
     15  RangeDeletion default     [u8=15][varint klen][begin][varint elen][end]
     16  CF RangeDeletion          [u8=16][varint cf_id][varint klen][begin][varint elen][end]
"""
import sys
import struct
import json
from pathlib import Path
from collections import defaultdict

import sys
sys.path.insert(0, str(Path(__file__).parent))
from _dataset_path import EXTRACTED_BASE, OSDS
BLOCK_SIZE = 32 * 1024
HEADER_LEGACY = 7
HEADER_RECYCLABLE = 11

# rocksdict.list_cf 결과 (단계 E-2): RocksDB MANIFEST 순서로 CF id 부여
CF_ID_MAP = {
    0: "default",
    1: "m-0", 2: "m-1", 3: "m-2",
    4: "p-0", 5: "p-1", 6: "p-2",
    7: "O-0", 8: "O-1", 9: "O-2",
    10: "L", 11: "P",
}

# CRC32C Castagnoli (standard with finalXOR)
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes) -> int:
    """Standard CRC32C with init=0xFFFFFFFF, finalXOR=0xFFFFFFFF."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


def crc32c_mask(crc: int) -> int:
    return (((crc >> 15) | ((crc << 17) & 0xFFFFFFFF)) + 0xa282ead8) & 0xFFFFFFFF


def read_varint(buf: bytes, off: int) -> tuple[int, int]:
    val, shift = 0, 0
    while True:
        b = buf[off]; off += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, off


def parse_wal_records(data: bytes) -> list[dict]:
    """WAL byte stream → records list (CRC verify 포함)."""
    records = []
    pos = 0
    n = len(data)
    while pos + HEADER_LEGACY <= n:
        # 현재 block 안 남은 byte
        block_off = pos % BLOCK_SIZE
        block_remain = BLOCK_SIZE - block_off
        # padding (header 안 들어가면 skip to next block)
        if block_remain < HEADER_LEGACY:
            pos += block_remain
            continue
        # peek type
        rec_type = data[pos + 6]
        if rec_type == 0:
            # zero padding — skip to next block
            pos += block_remain
            continue
        is_recyclable = rec_type in (5, 6, 7, 8)
        header_size = HEADER_RECYCLABLE if is_recyclable else HEADER_LEGACY
        if pos + header_size > n:
            break
        checksum_masked = struct.unpack_from("<I", data, pos)[0]
        length = struct.unpack_from("<H", data, pos + 4)[0]
        if is_recyclable:
            log_num = struct.unpack_from("<I", data, pos + 7)[0]
            payload_start = pos + HEADER_RECYCLABLE
        else:
            log_num = None
            payload_start = pos + HEADER_LEGACY
        payload_end = payload_start + length
        if payload_end > n:
            break
        payload = data[payload_start:payload_end]
        # CRC verify
        if is_recyclable:
            crc_input = bytes([rec_type]) + struct.pack("<I", log_num) + payload
        else:
            crc_input = bytes([rec_type]) + payload
        crc_computed = crc32c_mask(crc32c(crc_input))
        crc_ok = (crc_computed == checksum_masked)
        records.append({
            "pos": pos, "type": rec_type, "length": length,
            "log_num": log_num, "payload": payload, "crc_ok": crc_ok,
        })
        pos = payload_end
    return records


def assemble_writebatches(records: list[dict]) -> list[dict]:
    """fragment 들 reassemble → writebatch list."""
    out = []
    cur = None
    for rec in records:
        t = rec["type"]
        if t in (1, 5):  # Full
            out.append({
                "start_pos": rec["pos"], "payload": rec["payload"],
                "crc_ok": rec["crc_ok"], "fragments": 1,
            })
            cur = None
        elif t in (2, 6):  # First
            cur = {
                "start_pos": rec["pos"], "payload": rec["payload"],
                "crc_ok": rec["crc_ok"], "fragments": 1,
            }
        elif t in (3, 7):  # Middle
            if cur is not None:
                cur["payload"] += rec["payload"]
                cur["crc_ok"] = cur["crc_ok"] and rec["crc_ok"]
                cur["fragments"] += 1
        elif t in (4, 8):  # Last
            if cur is not None:
                cur["payload"] += rec["payload"]
                cur["crc_ok"] = cur["crc_ok"] and rec["crc_ok"]
                cur["fragments"] += 1
                out.append(cur)
                cur = None
    return out


def parse_writebatch(payload: bytes) -> tuple[list[dict], str | None]:
    """WriteBatch payload → ops list. Returns (ops, error_or_None)."""
    if len(payload) < 12:
        return [], "payload too short"
    seq = struct.unpack_from("<Q", payload, 0)[0]
    count = struct.unpack_from("<I", payload, 8)[0]
    pos = 12
    ops = []
    for i in range(count):
        if pos >= len(payload):
            return ops, f"truncated at op #{i}"
        op_type = payload[pos]; pos += 1
        try:
            cur_seq = seq + i
            if op_type == 1:    # PUT default CF
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                vlen, pos = read_varint(payload, pos)
                val = payload[pos:pos+vlen]; pos += vlen
                ops.append({"seq": cur_seq, "op": "PUT", "cf_id": 0, "key": key, "value": val})
            elif op_type == 5:  # PUT CF
                cf_id, pos = read_varint(payload, pos)
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                vlen, pos = read_varint(payload, pos)
                val = payload[pos:pos+vlen]; pos += vlen
                ops.append({"seq": cur_seq, "op": "PUT", "cf_id": cf_id, "key": key, "value": val})
            elif op_type == 0:  # DEL default
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                ops.append({"seq": cur_seq, "op": "DEL", "cf_id": 0, "key": key, "value": None})
            elif op_type == 4:  # DEL CF
                cf_id, pos = read_varint(payload, pos)
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                ops.append({"seq": cur_seq, "op": "DEL", "cf_id": cf_id, "key": key, "value": None})
            elif op_type == 7:  # SDEL default
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                ops.append({"seq": cur_seq, "op": "SDEL", "cf_id": 0, "key": key, "value": None})
            elif op_type == 8:  # SDEL CF
                cf_id, pos = read_varint(payload, pos)
                klen, pos = read_varint(payload, pos)
                key = payload[pos:pos+klen]; pos += klen
                ops.append({"seq": cur_seq, "op": "SDEL", "cf_id": cf_id, "key": key, "value": None})
            elif op_type == 15: # DELRANGE default
                klen, pos = read_varint(payload, pos)
                begin = payload[pos:pos+klen]; pos += klen
                elen, pos = read_varint(payload, pos)
                end = payload[pos:pos+elen]; pos += elen
                ops.append({"seq": cur_seq, "op": "DELRANGE", "cf_id": 0, "key": begin, "value": end})
            elif op_type == 16: # DELRANGE CF
                cf_id, pos = read_varint(payload, pos)
                klen, pos = read_varint(payload, pos)
                begin = payload[pos:pos+klen]; pos += klen
                elen, pos = read_varint(payload, pos)
                end = payload[pos:pos+elen]; pos += elen
                ops.append({"seq": cur_seq, "op": "DELRANGE", "cf_id": cf_id, "key": begin, "value": end})
            elif op_type == 13: # Noop
                ops.append({"seq": cur_seq, "op": "NOOP"})
            elif op_type in (9, 14):  # Begin Prepare XID variants
                ops.append({"seq": cur_seq, "op": "BEGIN_PREP"})
            elif op_type in (10, 11, 12):  # End Prepare / Commit / Rollback
                xlen, pos = read_varint(payload, pos)
                xid = payload[pos:pos+xlen]; pos += xlen
                ops.append({"seq": cur_seq, "op": ["?","?","?","?","?","?","?","?","?","?","ENDPREP","COMMIT","ROLLBACK"][op_type], "xid": xid})
            else:
                return ops, f"unknown op_type 0x{op_type:02x} at op #{i}"
        except IndexError as e:
            return ops, f"op decode IndexError at op #{i}: {e}"
    return ops, None


def parse_log_file(path: Path) -> dict:
    """한 .log 파일 파싱."""
    with open(path, "rb") as f:
        data = f.read()
    records = parse_wal_records(data)
    batches = assemble_writebatches(records)
    all_ops = []
    decode_errors = 0
    for batch in batches:
        if not batch["crc_ok"]:
            decode_errors += 1
            continue
        ops, err = parse_writebatch(batch["payload"])
        if err:
            decode_errors += 1
        all_ops.extend(ops)
    return {
        "file": path.name,
        "size": path.stat().st_size,
        "n_records": len(records),
        "n_batches": len(batches),
        "n_ops": len(all_ops),
        "n_decode_errors": decode_errors,
        "ops": all_ops,
        "first_seq": all_ops[0]["seq"] if all_ops else None,
        "last_seq": all_ops[-1]["seq"] if all_ops else None,
    }


def analyze_osd_wal(osd: str) -> dict:
    """한 OSD 의 db.wal/*.log 모두 파싱."""
    wal_dir = EXTRACTED_BASE / osd / "db.wal"
    log_files = sorted(wal_dir.glob("*.log"))
    per_file = []
    all_ops = []
    for log_path in log_files:
        info = parse_log_file(log_path)
        per_file.append({k: v for k, v in info.items() if k != "ops"})
        all_ops.extend(info["ops"])
    # sort by seq for global timeline
    all_ops.sort(key=lambda x: x.get("seq", 0))
    return {"osd": osd, "per_file": per_file, "all_ops": all_ops}


def main():
    print("=" * 90)
    print("단계 E-5 — RocksDB WAL 직접 파서")
    print("=" * 90)

    OUT_DIR = EXTRACTED_BASE / "_e5_wal_results"
    OUT_DIR.mkdir(exist_ok=True)

    # 사용자 지시 #4: R3 검증 — 옛/새 vm-100 id 안 search
    SEARCH_PATTERNS = {
        b"123e4b6cb66af0": "새 vm-100 (T3)",
        b"ff183be962b56":  "옛 vm-100 (T1)",
        b"fb9748b48c7e0":  "vm-101 (T1, deleted T2)",
        b"fba4d30439e46":  "vm-103 (T1, deleted T2)",
        b"rbd_directory":  "rbd_directory object",
    }

    for osd in OSDS:
        print(f"\n{'─' * 90}")
        print(f"{osd}")
        print(f"{'─' * 90}")
        result = analyze_osd_wal(osd)
        print(f"\n  per-file summary:")
        print(f"  {'file':<25s} {'size':>14s} {'records':>10s} {'batches':>10s} {'ops':>10s} {'errors':>8s} {'first_seq':>12s} {'last_seq':>12s}")
        for f in result["per_file"]:
            print(f"  {f['file']:<25s} {f['size']:>14,} {f['n_records']:>10d} {f['n_batches']:>10d} {f['n_ops']:>10d} {f['n_decode_errors']:>8d} {str(f['first_seq']):>12s} {str(f['last_seq']):>12s}")

        all_ops = result["all_ops"]
        n_total = len(all_ops)
        if n_total == 0:
            print(f"\n  → 0 ops parsed")
            continue

        # op type 분포
        by_op = defaultdict(int)
        by_cf = defaultdict(int)
        for op in all_ops:
            by_op[op["op"]] += 1
            if "cf_id" in op:
                by_cf[op["cf_id"]] += 1

        print(f"\n  total ops: {n_total:,}")
        print(f"  op type distribution:")
        for opn in sorted(by_op):
            print(f"    {opn:<10s} {by_op[opn]:>10,}")
        print(f"  CF distribution:")
        for cf_id in sorted(by_cf):
            cf_name = CF_ID_MAP.get(cf_id, f"?{cf_id}")
            print(f"    cf={cf_id:<3d} ({cf_name:<10s}) {by_cf[cf_id]:>10,}")

        seq_min = min(op["seq"] for op in all_ops if "seq" in op)
        seq_max = max(op["seq"] for op in all_ops if "seq" in op)
        print(f"  seq range: {seq_min} .. {seq_max}")

        # 사용자 지시 #4: R3 검증
        print(f"\n  R3 가설 검증 — pattern search in WAL ops:")
        for needle, label in SEARCH_PATTERNS.items():
            put_count = 0
            del_count = 0
            sdel_count = 0
            samples = []
            for op in all_ops:
                if "key" not in op:
                    continue
                if needle in op["key"] or (op.get("value") and needle in op["value"]):
                    if op["op"] == "PUT":
                        put_count += 1
                    elif op["op"] == "DEL":
                        del_count += 1
                    elif op["op"] == "SDEL":
                        sdel_count += 1
                    if len(samples) < 2:
                        samples.append(op)
            print(f"    {label:<30s} ({needle.decode():<18s}): PUT={put_count:>5d} DEL={del_count:>3d} SDEL={sdel_count:>3d}")
            for s in samples[:1]:
                key_ascii = ''.join(chr(c) if 32 <= c < 127 else '.' for c in s["key"][:60])
                val_ascii = ''
                if s.get("value"):
                    val_ascii = ''.join(chr(c) if 32 <= c < 127 else '.' for c in s["value"][:40])
                print(f"        sample: seq={s['seq']} cf={s.get('cf_id','?')} op={s['op']} key={key_ascii!r}")
                if val_ascii:
                    print(f"                value={val_ascii!r}")

        # 결과 저장 (사용자 조건 #3 — raw byte 형태)
        out_path = OUT_DIR / f"{osd}_wal_ops.bin"
        with open(out_path, "wb") as f:
            f.write(f"# {osd} WAL ops (total {n_total:,})\n".encode())
            f.write(f"# seq range: {seq_min} .. {seq_max}\n".encode())
            f.write(f"# format: per op: [u32 LE seq_lo][u32 LE seq_hi][u8 op_code][u8 cf_id][u32 LE klen][key][u32 LE vlen][value]\n".encode())
            f.write(b"#--OPS--\n")
            op_codes = {"PUT": 1, "DEL": 0, "SDEL": 7, "DELRANGE": 15, "NOOP": 13,
                        "BEGIN_PREP": 9, "ENDPREP": 10, "COMMIT": 11, "ROLLBACK": 12}
            for op in all_ops:
                if op["op"] not in op_codes:
                    continue
                seq = op.get("seq", 0)
                cf_id = op.get("cf_id", 255)
                key = op.get("key", b"")
                val = op.get("value", b"") or b""
                f.write(struct.pack("<QBB", seq, op_codes[op["op"]], cf_id))
                f.write(struct.pack("<I", len(key))); f.write(key)
                f.write(struct.pack("<I", len(val))); f.write(val)
        print(f"\n  raw ops 저장: {out_path.name}  ({out_path.stat().st_size:,} byte)")


if __name__ == "__main__":
    main()
