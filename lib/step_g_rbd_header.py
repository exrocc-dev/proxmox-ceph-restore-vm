"""
단계 G — rbd_header.<image_id> onode 의 OMAP → image_size · order · object_prefix 추출

대상 image_id 목록은 단계 F 결과(_f_results/f_union_summary.json) 의 활성 가상머신 +
잔재 후보(rbd_data chunk 가 있으나 rbd_header onode 가 없는 image_id) 를 동적으로 사용한다.

알고리즘 (단계 F 패턴 그대로):
  1. SST O-* CF 에서 'rbd_header.<image_id>' substring 매치 onode → nid 추출
  2. SST 에 없으면 WAL O-* CF PUT 에서 검색
  3. SST p-* CF iterate → nid_BE substring 매치 OMAP entries (baseline)
  4. WAL ops bin → cf ∈ {4,5,6} (p-*) AND key 안 nid_BE → ops (seq sorted)
  5. SST + WAL union by seq
  6. final OMAP 에서:
     - 'size' → u64 LE = image_size
     - 'order' → u8 = log2(object_size)
     - 'object_prefix' → [u32 LE len][ASCII]
     - 'snap_seq', 'features', 'flags', 'create_timestamp', 'access_timestamp', 'modify_timestamp'
"""
import sys
import struct
import json
from pathlib import Path
from collections import defaultdict
from rocksdict import Rdict, Options, AccessType

sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import read_denc_varint
from step_f_sst_wal_union import (
    iter_wal_ops, extract_user_key_from_omap_key, apply_omap_union,
    O_CF_IDS, P_CF_IDS, CF_NAME, OP_CODE,
    open_readonly,
)

from _dataset_path import EXTRACTED_BASE, OSDS


def load_target_image_ids() -> list[str]:
    """단계 F 결과 JSON 에서 분석 대상 image_id 를 동적으로 수집.

    수집 범위:
      - active: rbd_directory 의 'id_<image_id>' entry 가 final_omap 에 존재
      - chunk-present: rbd_data.<image_id>.<bn> 객체 onode 가 SST 나 WAL 에 존재
        (active 가상머신 + 삭제 진행 중인 잔재 모두 포함)
    """
    f_json = EXTRACTED_BASE / "_f_results" / "f_union_summary.json"
    image_ids: set[str] = set()
    if not f_json.exists():
        return []
    with open(f_json, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    for osd_name, osd_data in data.items():
        if not isinstance(osd_data, dict):
            continue
        # active vm: rbd_directory 의 id_<image_id> entry
        final_omap = osd_data.get("final_omap") or {}
        for key in final_omap.keys():
            if key.startswith("id_"):
                image_ids.add(key[3:])
        # chunk 가 발견된 image_id (chunk_union 의 키들)
        chunk_union = osd_data.get("chunk_union") or {}
        for iid in chunk_union.keys():
            image_ids.add(iid)
    return sorted(image_ids)


def find_nid_in_sst(db, cf_list, target_substring: bytes):
    """O-* CF iterate → target substring 매치 onode → nid 추출."""
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if target_substring in key:
                value = bytes(it.value())
                if len(value) >= 6:
                    sl = struct.unpack_from("<I", value, 2)[0]
                    body = value[6:6+sl]
                    nid, _ = read_denc_varint(body, 0)
                    return nid, cf_name, key, value
            it.next()
    return None


def find_nid_in_wal(osd: str, target_substring: bytes):
    """WAL ops bin scan → cf ∈ O-*, op=PUT, key 안 target → nid 추출.
       첫 매치만 반환 (모든 PUT 의 nid 동일)."""
    for seq, op_code, cf_id, key, val in iter_wal_ops(osd):
        if cf_id not in O_CF_IDS or op_code != 1:
            continue
        if target_substring in key:
            if len(val) >= 6:
                sl = struct.unpack_from("<I", val, 2)[0]
                body = val[6:6+sl]
                nid, _ = read_denc_varint(body, 0)
                return nid, cf_id, key, val, seq
    return None


def dump_sst_omap_for_nid(db, cf_list, nid: int) -> dict:
    """SST 의 p-*/m-* CF 안 nid_BE substring 매치 OMAP entries.
       반환: {user_key: (cf_name, key, value)}
    """
    nid_be = nid.to_bytes(8, "big")
    out = {}
    for cf_name in [c for c in cf_list if c.startswith("p-") or c.startswith("m-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if nid_be in key:
                user_key = extract_user_key_from_omap_key(key, nid_be)
                if user_key is not None:
                    out[user_key] = (cf_name, key, bytes(it.value()))
            it.next()
    return out


def collect_wal_omap_ops_for_nid(osd: str, nid: int) -> list:
    """WAL ops 안 cf ∈ p-* AND key 안 nid_BE → ops (seq sorted)."""
    nid_be = nid.to_bytes(8, "big")
    ops = []
    for seq, op_code, cf_id, key, val in iter_wal_ops(osd):
        if cf_id not in P_CF_IDS:
            continue
        if nid_be not in key:
            continue
        user_key = extract_user_key_from_omap_key(key, nid_be)
        if user_key is None:
            continue
        ops.append((seq, op_code, cf_id, user_key, val))
    ops.sort(key=lambda x: x[0])
    return ops


def decode_rbd_header_omap(final_omap: dict) -> dict:
    """rbd_header OMAP key 별 value decode."""
    out = {"_all_keys": [], "_decode_errors": []}
    for user_key, (src, seq, value) in final_omap.items():
        try:
            ks = user_key.decode('ascii')
        except UnicodeDecodeError:
            out["_decode_errors"].append({"key_hex": user_key.hex(), "reason": "non-ASCII key"})
            continue
        out["_all_keys"].append(ks)

        try:
            if ks == "size" and len(value) >= 8:
                out["size"] = struct.unpack_from("<Q", value)[0]
                out["size_src"] = src; out["size_seq"] = seq
            elif ks == "order" and len(value) >= 1:
                out["order"] = value[0]
                out["order_src"] = src; out["order_seq"] = seq
            elif ks == "object_prefix" and len(value) >= 4:
                L = struct.unpack_from("<I", value)[0]
                if 4 + L <= len(value):
                    out["object_prefix"] = value[4:4+L].decode("ascii", errors="replace")
                    out["object_prefix_src"] = src; out["object_prefix_seq"] = seq
            elif ks == "snap_seq" and len(value) >= 8:
                out["snap_seq"] = struct.unpack_from("<Q", value)[0]
            elif ks == "features" and len(value) >= 8:
                out["features"] = struct.unpack_from("<Q", value)[0]
            elif ks == "flags" and len(value) >= 8:
                out["flags"] = struct.unpack_from("<Q", value)[0]
            elif ks in ("create_timestamp", "access_timestamp", "modify_timestamp"):
                # utime_t = u32 sec + u32 nsec (LE) — 8 byte
                if len(value) >= 8:
                    sec = struct.unpack_from("<I", value, 0)[0]
                    nsec = struct.unpack_from("<I", value, 4)[0]
                    out[ks] = {"sec": sec, "nsec": nsec, "iso": iso_from_utime(sec, nsec)}
            elif ks == "stripe_unit" and len(value) >= 8:
                out["stripe_unit"] = struct.unpack_from("<Q", value)[0]
            elif ks == "stripe_count" and len(value) >= 8:
                out["stripe_count"] = struct.unpack_from("<Q", value)[0]
            elif ks == "data_pool_id":
                out["data_pool_id_hex"] = value.hex()
        except Exception as e:
            out["_decode_errors"].append({"key": ks, "reason": str(e)})
    out["_all_keys"].sort()
    return out


def iso_from_utime(sec: int, nsec: int) -> str:
    """utime_t (epoch UTC) → ISO 8601."""
    import datetime
    try:
        dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
        return f"{dt.isoformat()}.{nsec:09d}"
    except (ValueError, OSError):
        return f"<invalid: sec={sec}>"


def analyze_image_in_osd(db, cf_list, osd: str, image_id: str) -> dict:
    """한 OSD 에서 한 image 의 rbd_header OMAP 추출."""
    target_substring = f"rbd_header.{image_id}".encode()
    result = {
        "image_id": image_id,
        "osd": osd,
        "nid": None,
        "nid_src": None,  # "SST" / "WAL" / None
        "header_onode_present": False,
        "sst_omap_count": 0,
        "wal_ops_count": 0,
        "wal_breakdown": {"PUT": 0, "DEL": 0, "SDEL": 0},
        "final_omap_count": 0,
        "decoded": None,
        "status": "not_found",
    }

    # Step 1: SST 에서 onode + nid 찾기
    sst_hit = find_nid_in_sst(db, cf_list, target_substring)
    if sst_hit is not None:
        nid, cf_name, key, value = sst_hit
        result["nid"] = nid
        result["nid_src"] = "SST"
        result["nid_cf"] = cf_name
        result["header_onode_present"] = True
    else:
        # Step 2: WAL 에서 onode + nid 찾기
        wal_hit = find_nid_in_wal(osd, target_substring)
        if wal_hit is not None:
            nid, cf_id, key, val, seq = wal_hit
            result["nid"] = nid
            result["nid_src"] = "WAL"
            result["nid_cf"] = CF_NAME.get(cf_id, str(cf_id))
            result["nid_wal_seq"] = seq
            result["header_onode_present"] = True

    if result["nid"] is None:
        result["status"] = "no_rbd_header"
        return result

    # Step 3-4: SST + WAL OMAP collection
    nid = result["nid"]
    sst_omap = dump_sst_omap_for_nid(db, cf_list, nid)
    wal_ops = collect_wal_omap_ops_for_nid(osd, nid)

    result["sst_omap_count"] = len(sst_omap)
    result["wal_ops_count"] = len(wal_ops)
    for seq, op_code, cf_id, user_key, val in wal_ops:
        op_name = OP_CODE.get(op_code, f"?{op_code}")
        if op_name in result["wal_breakdown"]:
            result["wal_breakdown"][op_name] += 1

    # Step 5: union by seq
    final_omap = apply_omap_union(sst_omap, wal_ops)
    result["final_omap_count"] = len(final_omap)
    if not final_omap:
        result["status"] = "header_present_but_omap_empty"
        return result

    # Step 6: decode
    decoded = decode_rbd_header_omap(final_omap)
    result["decoded"] = decoded
    result["status"] = "decoded"
    return result


def main():
    print("=" * 100)
    print("단계 G — rbd_header OMAP 추출 (SST + WAL union)")
    print("=" * 100)

    OUT_DIR = EXTRACTED_BASE / "_g_results"
    OUT_DIR.mkdir(exist_ok=True)

    target_image_ids = load_target_image_ids()
    if not target_image_ids:
        print("  단계 F 결과 JSON 에서 분석 대상 image_id 를 찾지 못함.", file=sys.stderr)
        return

    all_results = {}  # osd -> image_id -> result

    for osd in OSDS:
        db_dir = EXTRACTED_BASE / osd / "db"
        if not (db_dir / "CURRENT").exists():
            print(f"\n  [{osd}] db/CURRENT 없음 — 빈 OSD 로 간주하고 skip")
            all_results[osd] = {}
            continue
        print(f"\n{'─' * 100}")
        print(f"  {osd}  ({db_dir})")
        print(f"{'─' * 100}")
        db, cf_list = open_readonly(db_dir)
        per_image = {}
        for image_id in target_image_ids:
            print(f"\n  [{osd}] image_id={image_id}")
            r = analyze_image_in_osd(db, cf_list, osd, image_id)
            print(f"    status={r['status']}  nid={r['nid']}  src={r['nid_src']}")
            print(f"    SST omap={r['sst_omap_count']}  WAL ops={r['wal_ops_count']} "
                  f"(PUT/DEL/SDEL={r['wal_breakdown']['PUT']}/{r['wal_breakdown']['DEL']}/"
                  f"{r['wal_breakdown']['SDEL']})  final={r['final_omap_count']}")
            if r.get("decoded"):
                d = r["decoded"]
                print(f"    decoded:")
                print(f"      size           = {d.get('size'):>13}  "
                      f"({d.get('size', 0) / 1024**3:.2f} GiB)" if d.get("size") else "      size           = (missing)")
                print(f"      order          = {d.get('order')}  "
                      f"(object_size = {1 << d.get('order', 0)} byte)" if d.get("order") is not None else "      order          = (missing)")
                print(f"      object_prefix  = {d.get('object_prefix', '(missing)')!r}")
                if "size" in d and "order" in d:
                    obj_size = 1 << d["order"]
                    chunk_count_derived = d["size"] // obj_size
                    print(f"      → chunk_count_derived = size/object_size = {chunk_count_derived:,}")
                if "snap_seq" in d:
                    print(f"      snap_seq       = {d['snap_seq']}")
                if "features" in d:
                    print(f"      features       = 0x{d['features']:016x}")
                if "flags" in d:
                    print(f"      flags          = 0x{d['flags']:016x}")
                for ts_key in ("create_timestamp", "access_timestamp", "modify_timestamp"):
                    if ts_key in d:
                        print(f"      {ts_key:<14s} = {d[ts_key]['iso']}")
                print(f"      OMAP keys      = {d['_all_keys']}")
            per_image[image_id] = r
        db.close()
        all_results[osd] = per_image

    # ─── 종합 ───
    print(f"\n{'━' * 100}")
    print("종합 — image_id 별 image_size / order / object_prefix (OSD 비교)")
    print(f"{'━' * 100}")

    print(f"\n  {'image_id':<18s} | {'osd':<5s} {'src':<4s} {'nid':>6s} "
          f"{'size (byte)':>14s} {'GiB':>6s} {'order':>5s} {'derived':>8s} {'object_prefix':<30s}")
    print("  " + "-" * 110)

    for image_id in target_image_ids:
        for osd in OSDS:
            r = all_results.get(osd, {}).get(image_id) or {}
            d = r.get("decoded") or {}
            size = d.get("size", 0)
            order = d.get("order", 0)
            prefix = d.get("object_prefix", "")
            derived = (size // (1 << order)) if order else 0
            print(f"  {image_id:<18s} | {osd:<5s} {str(r.get('nid_src') or '-'):<4s} "
                  f"{str(r.get('nid') or '-'):>6s} {size:>14,} {(size/1024**3):>6.2f} {order:>5} "
                  f"{derived:>8,} {prefix[:29]:<30s}")
        print()

    # ─── JSON 저장 ───
    out_json = OUT_DIR / "g_summary.json"
    serializable = {}
    for osd, per_image in all_results.items():
        serializable[osd] = {}
        for image_id, r in per_image.items():
            d = r.get("decoded") or {}
            serializable[osd][image_id] = {
                "nid": r.get("nid"),
                "nid_src": r.get("nid_src"),
                "header_onode_present": r.get("header_onode_present"),
                "sst_omap_count": r.get("sst_omap_count", 0),
                "wal_ops_count": r.get("wal_ops_count", 0),
                "wal_breakdown": r.get("wal_breakdown"),
                "final_omap_count": r.get("final_omap_count", 0),
                "status": r.get("status"),
                "decoded": d,
            }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON 저장: {out_json}")


if __name__ == "__main__":
    main()
