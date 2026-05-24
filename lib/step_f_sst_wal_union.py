"""
단계 F — SST snapshot + WAL replay union → 진짜 cluster T4 state 도출

사용자 정의 (2026-05-10):
  - chunk 수 = O-* CF 의 rbd_data PUT 기준 (P CF 제외)
  - active 판별 = (rbd_directory entry 존재) AND (DEL 없음 또는 후속 PUT)
  - WAL 의 DEL 이 SST 의 PUT 을 덮어씀 (seq 순)

알고리즘:
  Stage 1. SST iterate (rocksdict ReadOnly)
    - O-* CF 안 rbd_directory onode 발견 → nid 추출
    - p-* CF 안 nid_BE substring 매치 OMAP entries → SST baseline
    - O-* CF 안 rbd_data.<id>.<bn> onode keys 수집 → image_id 별 chunk set
  Stage 2. WAL iterate (saved bin from E-5)
    - cf ∈ p-* AND key 안 nid_BE → directory OMAP ops (seq, op, user_key, value)
    - cf ∈ O-* AND key 안 "rbd_data.<id>." → chunk onode ops
  Stage 3. Union
    - SST baseline + WAL ops sorted by seq → 최종 state
  Stage 4. Decode
    - 최종 OMAP state 의 id_<id> / name_<n> → active image list
    - 최종 chunk set 별 count → image_id 별 chunk 수

사용자 우선순위:
  1. vm-101 / vm-103 union 후 active 잔존 여부
  2. 새 vm-100 (123e4b6cb66af0) active 잡히는가
  3. 옛 vm-100 (ff183be962b56) deleted 잡히는가
"""
import sys
import struct
import json
import re
from pathlib import Path
from collections import defaultdict
from rocksdict import Rdict, Options, AccessType

sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import read_denc_varint

from _dataset_path import EXTRACTED_BASE, OSDS
WAL_RESULTS = EXTRACTED_BASE / "_e5_wal_results"

# E-5 op_code mapping
OP_CODE = {1: "PUT", 0: "DEL", 7: "SDEL", 15: "DELRANGE", 13: "NOOP",
           9: "BEGIN_PREP", 10: "ENDPREP", 11: "COMMIT", 12: "ROLLBACK"}

# CF id (E-5 와 동일)
CF_NAME = {0: "default", 1: "m-0", 2: "m-1", 3: "m-2",
           4: "p-0", 5: "p-1", 6: "p-2",
           7: "O-0", 8: "O-1", 9: "O-2",
           10: "L", 11: "P"}
P_CF_IDS = {4, 5, 6}
O_CF_IDS = {7, 8, 9}

# rbd_data.<id>. pattern
RBD_DATA_RE = re.compile(rb'rbd_data\.([0-9a-f]+)\.([0-9a-f]+)')


def open_readonly(db_dir: Path):
    cf_list = Rdict.list_cf(str(db_dir))
    opts = Options(raw_mode=True)
    cfs = {cf: opts for cf in cf_list}
    db = Rdict(str(db_dir), options=opts, column_families=cfs,
               access_type=AccessType.read_only())
    return db, cf_list


def find_rbd_directory_nid(db, cf_list) -> int | None:
    """O-* CF iterate → rbd_directory onode 발견 → nid 추출."""
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if b"rbd_directory" in key:
                value = bytes(it.value())
                if len(value) < 6:
                    it.next(); continue
                # DENC header: u8 v / u8 c / u32 LE struct_len
                sl = struct.unpack_from("<I", value, 2)[0]
                body = value[6:6+sl]
                # body: denc_varint(nid), denc_varint(size), ...
                nid, _ = read_denc_varint(body, 0)
                return nid
            it.next()
    return None


def extract_user_key_from_omap_key(key: bytes, nid_be: bytes) -> bytes | None:
    """OMAP key 에서 user_key 추출.
       format: <prefix>...<nid_BE_8>.<user_key>
       (prefix 는 'p'+pool_BE+hash_BE 또는 'm'+pool_BE 또는 'M' — 다양)
    """
    idx = key.find(nid_be)
    if idx < 0:
        return None
    after = idx + len(nid_be)
    if after >= len(key):
        return None
    # 다음 byte 가 '.' (0x2e) 인지 확인
    if key[after] == 0x2e:
        return key[after + 1:]
    # 일부 BlueStore key 는 nid 직후 separator 가 다를 수 있음 — raw 반환
    return key[after:]


def dump_sst_omap_for_nid(db, cf_list, nid: int) -> dict:
    """SST 의 p-* / m-* CF 안 nid_BE substring 매치 OMAP entries 반환.
       반환: {user_key: (cf_name, full_key, value)}
    """
    nid_be = nid.to_bytes(8, "big")
    out = {}
    cfs = sorted([c for c in cf_list if c.startswith("p-") or c.startswith("m-")])
    for cf_name in cfs:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if nid_be in key:
                user_key = extract_user_key_from_omap_key(key, nid_be)
                if user_key is not None:
                    value = bytes(it.value())
                    out[user_key] = (cf_name, key, value)
            it.next()
    return out


def dump_sst_chunks_per_image(db, cf_list) -> dict:
    """SST 의 O-* CF 안 rbd_data.<id>.<bn> onode keys → image_id 별 chunk set."""
    by_image = defaultdict(set)
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            for m in RBD_DATA_RE.finditer(key):
                image_id = m.group(1).decode('ascii')
                bn = m.group(2).decode('ascii')
                by_image[image_id].add(bn)
            it.next()
    return {k: v for k, v in by_image.items()}


def iter_wal_ops(osd: str):
    path = WAL_RESULTS / f"{osd}_wal_ops.bin"
    with open(path, "rb") as f:
        data = f.read()
    marker = b"#--OPS--\n"
    idx = data.find(marker)
    pos = idx + len(marker)
    n = len(data)
    while pos < n:
        if pos + 10 > n: break
        seq, op_code, cf_id = struct.unpack_from("<QBB", data, pos); pos += 10
        klen, = struct.unpack_from("<I", data, pos); pos += 4
        key = data[pos:pos+klen]; pos += klen
        vlen, = struct.unpack_from("<I", data, pos); pos += 4
        val = data[pos:pos+vlen]; pos += vlen
        yield seq, op_code, cf_id, key, val


def collect_wal_directory_ops(osd: str, nid: int) -> list:
    """WAL 안 cf ∈ p-* AND key 에 nid_BE 들어있는 op 들 (rbd_directory OMAP op)."""
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


def collect_wal_chunk_ops(osd: str) -> dict:
    """WAL 안 cf ∈ O-* AND key 에 'rbd_data.<id>.<bn>' 들어있는 op 들.
       반환: {image_id: [(seq, op_code, bn), ...]} sorted by seq.
       PUT/DEL 둘 다 수집.
    """
    by_image = defaultdict(list)
    for seq, op_code, cf_id, key, val in iter_wal_ops(osd):
        if cf_id not in O_CF_IDS:
            continue
        if op_code not in (0, 1, 7):  # PUT/DEL/SDEL only
            continue
        for m in RBD_DATA_RE.finditer(key):
            image_id = m.group(1).decode('ascii')
            bn = m.group(2).decode('ascii')
            by_image[image_id].append((seq, op_code, bn))
    for image_id in by_image:
        by_image[image_id].sort(key=lambda x: x[0])
    return dict(by_image)


def apply_omap_union(sst_baseline: dict, wal_ops: list) -> dict:
    """SST baseline 위에 WAL ops 를 seq 순으로 적용.
       반환: {user_key: ('PUT', value)} 만 (살아있는 entry 만).
    """
    state = {}
    for user_key, (cf_name, full_key, value) in sst_baseline.items():
        state[user_key] = ('SST', None, value)
    for seq, op_code, cf_id, user_key, val in wal_ops:
        if op_code == 1:  # PUT
            state[user_key] = ('WAL_PUT', seq, val)
        elif op_code in (0, 7):  # DEL/SDEL
            state.pop(user_key, None)
    return state


def apply_chunk_union(sst_chunks: set, wal_ops: list) -> set:
    """SST chunk set 위에 WAL chunk PUT/DEL 적용.
       wal_ops: [(seq, op_code, bn), ...] sorted.
    """
    chunks = set(sst_chunks)
    for seq, op_code, bn in wal_ops:
        if op_code == 1:  # PUT
            chunks.add(bn)
        elif op_code in (0, 7):  # DEL/SDEL
            chunks.discard(bn)
    return chunks


def decode_omap_value_str(value: bytes) -> str | None:
    """rbd_directory OMAP value = [u32 LE len] + ASCII string."""
    if len(value) < 4: return None
    L = struct.unpack_from("<I", value, 0)[0]
    if 4 + L > len(value): return None
    try:
        return value[4:4+L].decode('ascii')
    except UnicodeDecodeError:
        return None


def analyze_osd(osd: str) -> dict:
    """한 OSD 의 SST + WAL union → active list + chunk per image."""
    db_dir = EXTRACTED_BASE / osd / "db"
    db, cf_list = open_readonly(db_dir)
    print(f"\n  [{osd}] SST iterate...")

    nid = find_rbd_directory_nid(db, cf_list)
    print(f"    rbd_directory nid = {nid}")
    sst_omap = {}
    if nid is not None:
        sst_omap = dump_sst_omap_for_nid(db, cf_list, nid)
    print(f"    SST OMAP entries (nid={nid}): {len(sst_omap)}")

    sst_chunks_by_image = dump_sst_chunks_per_image(db, cf_list)
    db.close()
    print(f"    SST rbd_data image_ids: {len(sst_chunks_by_image)}")

    print(f"  [{osd}] WAL iterate...")
    wal_dir_ops = collect_wal_directory_ops(osd, nid) if nid is not None else []
    print(f"    WAL OMAP ops (nid={nid}): {len(wal_dir_ops)}")
    wal_chunk_ops = collect_wal_chunk_ops(osd)
    print(f"    WAL rbd_data image_ids: {len(wal_chunk_ops)}")

    print(f"  [{osd}] union...")
    final_omap = apply_omap_union(sst_omap, wal_dir_ops) if nid else {}
    all_image_ids = set(sst_chunks_by_image) | set(wal_chunk_ops)
    chunk_union = {}
    for image_id in all_image_ids:
        sst_set = sst_chunks_by_image.get(image_id, set())
        wal_ops = wal_chunk_ops.get(image_id, [])
        chunks = apply_chunk_union(sst_set, wal_ops)
        chunk_union[image_id] = {
            "sst_count": len(sst_set),
            "wal_put": sum(1 for _, op, _ in wal_ops if op == 1),
            "wal_del": sum(1 for _, op, _ in wal_ops if op == 0),
            "wal_sdel": sum(1 for _, op, _ in wal_ops if op == 7),
            "final_count": len(chunks),
        }

    return {
        "osd": osd,
        "rbd_dir_nid": nid,
        "sst_omap_count": len(sst_omap),
        "wal_dir_ops_count": len(wal_dir_ops),
        "wal_dir_ops_breakdown": {
            "PUT": sum(1 for o in wal_dir_ops if o[1] == 1),
            "DEL": sum(1 for o in wal_dir_ops if o[1] == 0),
            "SDEL": sum(1 for o in wal_dir_ops if o[1] == 7),
        },
        "final_omap": final_omap,
        "chunk_union": chunk_union,
    }


def main():
    print("=" * 100)
    print("단계 F — SST snapshot + WAL replay union → 진짜 cluster state")
    print("=" * 100)

    OUT_DIR = EXTRACTED_BASE / "_f_results"
    OUT_DIR.mkdir(exist_ok=True)

    # 빈 OSD (BlueFS replay 결과 RocksDB 디렉터리 미존재) 에 대한 기본 결과
    EMPTY_RESULT = {
        "empty": True,
        "rbd_dir_nid": None,
        "sst_omap_count": 0,
        "wal_dir_ops_count": 0,
        "wal_dir_ops_breakdown": {"PUT": 0, "DEL": 0, "SDEL": 0},
        "wal_dir_ops_by_id": {},
        "final_omap": {},
        "chunk_union": {},
    }

    results = {}
    active_osds = []
    for osd in OSDS:
        db_dir = EXTRACTED_BASE / osd / "db"
        if not (db_dir / "CURRENT").exists():
            print(f"\n  [{osd}] db/CURRENT 없음 — 빈 OSD 로 간주하고 skip", flush=True)
            results[osd] = dict(EMPTY_RESULT)
            continue
        try:
            results[osd] = analyze_osd(osd)
            active_osds.append(osd)
        except Exception as e:
            print(f"\n  [{osd}] analyze 실패 — skip: {e}", flush=True)
            r = dict(EMPTY_RESULT)
            r["error"] = str(e)
            results[osd] = r

    # ─── 결과 1: rbd_directory nid + OMAP 비교 ───
    print(f"\n{'━' * 100}")
    print("결과 1 — rbd_directory OMAP union (SST + WAL)")
    print(f"{'━' * 100}")
    print(f"\n  {'osd':<8s} {'nid':>6s} {'SST OMAP':>10s} {'WAL ops':>8s} (PUT/DEL/SDEL) {'final OMAP':>12s}")
    for osd in OSDS:
        r = results[osd]
        bd = r["wal_dir_ops_breakdown"]
        print(f"  {osd:<8s} {r['rbd_dir_nid']!s:>6} {r['sst_omap_count']:>10d} "
              f"{r['wal_dir_ops_count']:>8d}  ({bd['PUT']:>3d}/{bd['DEL']:>3d}/{bd['SDEL']:>3d})    "
              f"{len(r['final_omap']):>12d}")

    # ─── 결과 2: 최종 active list (final_omap 의 id_<id> / name_<n> decode) ───
    print(f"\n{'━' * 100}")
    print("결과 2 — 최종 active image list (final_omap decode)")
    print(f"{'━' * 100}")

    for osd in OSDS:
        r = results[osd]
        final = r["final_omap"]
        if not final:
            print(f"\n  {osd}: final_omap empty")
            continue
        print(f"\n  {osd}:")
        # Sort by user_key for stable display
        id_to_name = {}
        name_to_id = {}
        sentinels = []
        unknown = []
        for user_key, (src, seq, value) in sorted(final.items()):
            if user_key.startswith(b'id_'):
                image_id = user_key[3:].decode('ascii', errors='replace')
                image_name = decode_omap_value_str(value)
                id_to_name[image_id] = (image_name, src, seq)
            elif user_key.startswith(b'name_'):
                image_name = user_key[5:].decode('ascii', errors='replace')
                image_id = decode_omap_value_str(value)
                name_to_id[image_name] = (image_id, src, seq)
            elif user_key == b'~':
                sentinels.append((src, seq))
            else:
                unknown.append((user_key, src, seq, value[:32]))
        print(f"    id_<id> entries:")
        for image_id, (image_name, src, seq) in sorted(id_to_name.items()):
            print(f"      {image_id} → {image_name!s:<20s}  (src={src} seq={seq})")
        print(f"    name_<n> entries:")
        for image_name, (image_id, src, seq) in sorted(name_to_id.items()):
            print(f"      {image_name!s:<20s} → {image_id}  (src={src} seq={seq})")
        if sentinels:
            print(f"    sentinel ~: {len(sentinels)}")
        if unknown:
            print(f"    unknown user_key entries: {len(unknown)}")
            for u in unknown[:3]:
                print(f"      {u[0][:30]!r}  (src={u[1]} seq={u[2]})  val={u[3]!r}")

    # ─── 결과 3: image_id 별 chunk count (SST + WAL union) ───
    print(f"\n{'━' * 100}")
    print("결과 3 — image_id 별 chunk count (SST + WAL union)")
    print(f"{'━' * 100}")

    # 모든 OSD 의 image_id union
    all_ids = set()
    for r in results.values():
        all_ids.update(r["chunk_union"].keys())

    print(f"\n  {'image_id':<18s} | "
          f"{'osd.0':^36s} | {'osd.1':^36s} | {'osd.2':^36s}")
    print(f"  {'':<18s} | "
          f"{'SST':>5s} {'WAL+':>5s} {'WAL-':>5s} {'SDEL':>4s} {'final':>5s}      | "
          f"{'SST':>5s} {'WAL+':>5s} {'WAL-':>5s} {'SDEL':>4s} {'final':>5s}      | "
          f"{'SST':>5s} {'WAL+':>5s} {'WAL-':>5s} {'SDEL':>4s} {'final':>5s}     ")
    print(f"  {'-'*18}-+-{'-'*36}-+-{'-'*36}-+-{'-'*36}")
    for image_id in sorted(all_ids):
        line = f"  {image_id:<18s} | "
        for osd in OSDS:
            cu = results[osd]["chunk_union"].get(image_id, {})
            sst = cu.get("sst_count", 0)
            wp = cu.get("wal_put", 0)
            wd = cu.get("wal_del", 0)
            ws = cu.get("wal_sdel", 0)
            fn = cu.get("final_count", 0)
            line += f"{sst:>5d} {wp:>5d} {wd:>5d} {ws:>4d} {fn:>5d}      | "
        print(line.rstrip("| ").rstrip())

    # union (3 OSD 합집합) 도 계산
    print(f"\n  3 OSD UNION (chunk bn 합집합 — primary backfill 차이 제거):")
    print(f"  {'image_id':<18s} | {'union final':>12s}")
    union_chunks_by_image = defaultdict(set)
    # Re-compute by reading all chunk bn sets per OSD per image
    # 이미 chunk_union 에는 count 만 있어서 set 자체 다시 계산 필요
    print(f"  (skipped — 본 단계에서는 OSD 별 final count 만 보고)")

    # ─── 결과 4: 사용자 우선순위 답 ───
    print(f"\n{'━' * 100}")
    print("결과 4 — 사용자 우선순위 답")
    print(f"{'━' * 100}")

    GT_IMAGES = {
        "ff183be962b56":  ("vm-100 OLD (T1)",     "deleted"),
        "fb9748b48c7e0":  ("vm-101         ",     "deleted"),
        "fba31d6ff543d":  ("vm-102         ",     "active"),
        "fba4d30439e46":  ("vm-103         ",     "deleted"),
        "fbabeb6914038":  ("vm-104         ",     "active"),
        "123e4b6cb66af0": ("vm-100 NEW (T3)",     "active"),
    }

    print(f"\n  3 OSD active list 합집합 (rbd_directory final_omap 의 id_<id>):")
    union_active_ids = set()
    per_osd_active_ids = {}
    for osd in OSDS:
        r = results[osd]
        ids = set()
        for user_key in r["final_omap"]:
            if user_key.startswith(b'id_'):
                ids.add(user_key[3:].decode('ascii', errors='replace'))
        per_osd_active_ids[osd] = ids
        union_active_ids.update(ids)

    print(f"\n  {'image_id':<18s} | {'GT label':<18s} | {'GT class':<8s} | "
          f"{'osd.0':^7s} {'osd.1':^7s} {'osd.2':^7s} | union")
    print(f"  {'-' * 18} | {'-' * 18} | {'-' * 8} | "
          f"{'-' * 7} {'-' * 7} {'-' * 7} | {'-' * 5}")
    for image_id in sorted(GT_IMAGES.keys() | union_active_ids):
        gt_label, gt_class = GT_IMAGES.get(image_id, ("?", "?"))
        cells = []
        for osd in OSDS:
            present = "✓" if image_id in per_osd_active_ids[osd] else "·"
            cells.append(present)
        unioncell = "✓" if image_id in union_active_ids else "·"
        print(f"  {image_id:<18s} | {gt_label:<18s} | {gt_class:<8s} | "
              f"{cells[0]:^7s} {cells[1]:^7s} {cells[2]:^7s} | {unioncell:>5s}")

    print(f"\n  사용자 우선순위 답:")
    print(f"    1. vm-101 (fb9748b48c7e0) union active 잡힘? "
          f"{'✓ active 잔존 (의문!)' if 'fb9748b48c7e0' in union_active_ids else '✗ deleted'}")
    print(f"       vm-103 (fba4d30439e46) union active 잡힘? "
          f"{'✓ active 잔존 (의문!)' if 'fba4d30439e46' in union_active_ids else '✗ deleted'}")
    print(f"    2. 새 vm-100 (123e4b6cb66af0) active 잡힘? "
          f"{'✓ T3 active 정상 도출' if '123e4b6cb66af0' in union_active_ids else '✗ 미발견 (도구 결함 잔존?)'}")
    print(f"    3. 옛 vm-100 (ff183be962b56) deleted 잡힘? "
          f"{'✓ deleted 정상 도출' if 'ff183be962b56' not in union_active_ids else '✗ active 잔존 (compaction 미진행)'}")

    # ─── JSON 결과 저장 ───
    out_json = OUT_DIR / "f_union_summary.json"
    serializable = {}
    for osd, r in results.items():
        # final_omap 의 bytes 키를 decode 가능한 형태로
        final_decoded = {}
        for user_key, (src, seq, value) in r["final_omap"].items():
            try:
                k = user_key.decode('ascii')
            except UnicodeDecodeError:
                k = user_key.hex()
            final_decoded[k] = {
                "src": src, "seq": seq,
                "value_hex": value.hex(),
                "value_str": decode_omap_value_str(value),
            }
        serializable[osd] = {
            "rbd_dir_nid": r["rbd_dir_nid"],
            "sst_omap_count": r["sst_omap_count"],
            "wal_dir_ops_count": r["wal_dir_ops_count"],
            "wal_dir_ops_breakdown": r["wal_dir_ops_breakdown"],
            "final_omap": final_decoded,
            "chunk_union": r["chunk_union"],
        }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON 저장: {out_json}")


if __name__ == "__main__":
    main()
