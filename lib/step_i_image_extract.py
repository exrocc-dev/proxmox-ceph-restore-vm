"""
단계 I — image 추출 라이브러리 (chunk byte 단위 회수 함수 집합)

알고리즘:
  1. SST + WAL union 으로 image 의 모든 chunk onode + shard 수집
  2. 각 unique chunk bn 의 final onode value 결정
  3. onode parse → n_shards > 0 이면 shards fetch + parse → 4 MiB chunk byte 추출
                  → n_shards == 0 이면 inline extent_map (필요 시 추가 구현)
  4. image_buf[bn × 4 MiB : (bn+1) × 4 MiB] = chunk bytes (없으면 0 fill)

본 모듈은 step_i_union_5osd.py 가 import 하여 사용하는 라이브러리이다.
"""
import sys
import struct
import hashlib
import json
import re
from pathlib import Path
from collections import defaultdict
from rocksdict import Rdict, Options, AccessType

sys.path.insert(0, str(Path(__file__).parent))
from step_d_bluefs_replay import read_denc_varint, PV_LV_OFFSET
from step_f_sst_wal_union import (
    open_readonly, iter_wal_ops, O_CF_IDS, RBD_DATA_RE,
)
from step_h1_dump_chunk_onode import parse_onode
from step_h_chunk_extract import (
    parse_shard, parse_blob, parse_pextent, parse_spanning_blobs,
    read_denc_varint_lowz, read_denc_lba,
    OSD_RAW,
)

from _dataset_path import EXTRACTED_BASE, OSDS


def load_image_metadata(image_id: str) -> dict | None:
    """단계 G 결과(_g_results/g_summary.json) 에서 image 의 size·order·object_prefix·vm_name 조회.

    여러 OSD 에 같은 image 의 메타가 있으면 가장 먼저 발견된 OSD 의 디코드 값을 채택한다.
    OSD 간 메타 불일치는 단계 G 가 "종합" 표로 출력하므로 본 함수는 첫 번째 유효 값만 반환.

    vm_name 은 단계 F 결과(_f_results/f_union_summary.json) 의 rbd_directory entries
    (id_<image_id> → vm name) 에서 조회한다.

    Returns:
      {"image_size": int, "order": int, "object_prefix": str, "vm_name": str} 또는 None
    """
    g_json = EXTRACTED_BASE / "_g_results" / "g_summary.json"
    image_size = order = None
    object_prefix = ""
    if g_json.exists():
        with open(g_json, "r", encoding="utf-8") as fh:
            g_data = json.load(fh)
        for osd_name, per_image in g_data.items():
            if not isinstance(per_image, dict):
                continue
            entry = per_image.get(image_id) or {}
            d = entry.get("decoded") or {}
            if "size" in d and "order" in d:
                image_size = d["size"]
                order = d["order"]
                object_prefix = d.get("object_prefix", "")
                break

    vm_name = ""
    f_json = EXTRACTED_BASE / "_f_results" / "f_union_summary.json"
    if f_json.exists():
        with open(f_json, "r", encoding="utf-8") as fh:
            f_data = json.load(fh)
        for osd_name, osd_data in f_data.items():
            if not isinstance(osd_data, dict):
                continue
            final_omap = osd_data.get("final_omap") or {}
            entry = final_omap.get(f"id_{image_id}") or {}
            cand = entry.get("value_str") if isinstance(entry, dict) else ""
            if cand:
                vm_name = cand
                break

    if image_size is None or order is None:
        return None
    return {
        "image_size": image_size,
        "order": order,
        "object_prefix": object_prefix,
        "vm_name": vm_name or f"image-{image_id}",
    }


def collect_sst_state(db, cf_list, image_id: str) -> dict:
    """SST 의 O-* CF 안 'rbd_data.<image_id>.' 매치 entries 수집.
       반환: {full_key: value}
    """
    target = f"rbd_data.{image_id}.".encode()
    state = {}
    for cf_name in [c for c in cf_list if c.startswith("O-")]:
        cf = db.get_column_family(cf_name)
        it = cf.iter()
        it.seek_to_first()
        while it.valid():
            key = bytes(it.key())
            if target in key:
                state[key] = bytes(it.value())
            it.next()
    return state


def apply_wal_state(state: dict, osd: str, image_id: str) -> tuple[int, int]:
    """WAL ops 를 SST state 위에 seq 순으로 적용.
       반환: (n_put_applied, n_del_applied)
    """
    target = f"rbd_data.{image_id}.".encode()
    # WAL ops 는 step_e5 saved bin 에서 가져옴; 단 seq 순 보장 필요
    # iter_wal_ops 가 WAL parse 순으로 yield (이미 seq 순으로 sorted 되어 있음 -- E-5 분석 후)
    # 안전을 위해 본 도구는 WAL 의 모든 매치 op 를 list 로 모아서 seq sort
    ops = []
    for seq, op_code, cf_id, key, val in iter_wal_ops(osd):
        if cf_id not in O_CF_IDS:
            continue
        if target not in key:
            continue
        ops.append((seq, op_code, key, val))
    ops.sort(key=lambda x: x[0])

    n_put = 0
    n_del = 0
    for seq, op_code, key, val in ops:
        if op_code == 1:   # PUT
            state[key] = val
            n_put += 1
        elif op_code in (0, 7):   # DEL/SDEL
            state.pop(key, None)
            n_del += 1
    return n_put, n_del


def parse_chunk_key_bn(key: bytes, image_id: str) -> int | None:
    """onode key 에서 chunk bn 추출 (key 끝이 'o')."""
    if not key.endswith(b'o'):
        return None
    target = f"rbd_data.{image_id}.".encode()
    idx = key.find(target)
    if idx < 0:
        return None
    after = idx + len(target)
    # 다음 16 hex chars 가 bn
    hex_part = bytes(key[after:after+16])
    try:
        bn_str = hex_part.decode('ascii')
        if len(bn_str) != 16: return None
        # validate hex
        int(bn_str, 16)
        return int(bn_str, 16)
    except (UnicodeDecodeError, ValueError):
        return None


def extract_chunk(state: dict, onode_key: bytes, onode_value: bytes,
                  raw_path: Path) -> tuple[bytes, dict]:
    """단계 H 의 logic 재사용 — onode + shards (state 에서 fetch) → 4 MiB byte."""
    chunk_size = 4 * 1024 * 1024
    out_buf = bytearray(chunk_size)
    info = {"shards_fetched": 0, "shards_missing": 0, "extents": 0, "errors": []}

    on = parse_onode(onode_value)
    if "error" in on:
        info["errors"].append(f"onode parse: {on['error']}")
        return bytes(out_buf), info

    n_shards = on.get("n_shards", 0)

    INVALID_PEXTENT = 0xFFFFFFFFFFFFFFFF

    def apply_extents_from_shard(shard: dict):
        """parsed shard 의 extents → out_buf 의 logical 위치에 disk bytes 복사.
           pextent.offset == 0xFFFFFFFFFFFFFFFF (INVALID) 은 hole = zero-fill."""
        if "extents" not in shard:
            return
        for ext in shard["extents"]:
            if "blob" not in ext:
                continue
            blob = ext["blob"]
            blob_off = ext["blob_offset"]
            length = ext["length"]
            log_off = ext["logical_offset"]
            cum = 0
            extracted = bytearray()
            remaining = length
            for pe in blob["extents"]:
                pe_len = pe["length"]
                pe_off = pe["offset"]
                if cum + pe_len <= blob_off:
                    cum += pe_len; continue
                rel = blob_off - cum if cum < blob_off else 0
                avail = pe_len - rel
                take = min(avail, remaining)
                if pe_off == INVALID_PEXTENT:
                    # hole — zero-fill
                    extracted += b'\x00' * take
                else:
                    start_in_pe = pe_off + rel
                    with open(raw_path, "rb") as f:
                        f.seek(start_in_pe + PV_LV_OFFSET)
                        disk_bytes = f.read(take)
                    extracted += disk_bytes
                remaining -= take
                cum += pe_len
                if remaining <= 0: break
            if log_off + length <= chunk_size:
                out_buf[log_off:log_off + length] = extracted
                info["extents"] += 1

    # k10 정정: tail 에서 spanning_blob_map 먼저 parse (sp_n > 0 면 lookup 가능).
    # tail format (BlueStore.cc:17944-17963):
    #   [encode_spanning_blobs() output: u8 sp_v + varint sp_n + sp_n × {varint blob_id + Blob::encode}]
    #   [if n_shards == 0: inline_bl (= [u32 LE bl_len][bl_len bytes shard])]
    struct_len = on.get("struct_len", 0)
    tail_start = 6 + struct_len
    tail_off = 0
    spanning_blob_map = {}
    if tail_start < len(onode_value):
        tail = onode_value[tail_start:]
        sp_meta, tail_off, spanning_blob_map = parse_spanning_blobs(tail, 0)
        info["spanning_n"] = sp_meta.get("sp_n", 0)
        if "error" in sp_meta:
            info["errors"].append(f"spanning_blob_map parse: {sp_meta['error']}")

    if n_shards == 0:
        # inline extent_map — spanning_blob_map 뒤에 [u32 LE inline_len][inline shard] 위치
        tail = onode_value[tail_start:]
        # spanning_blob_map 끝 (tail_off) 이후가 inline_bl
        if tail_off + 4 > len(tail):
            info["errors"].append(f"inline: tail too short after spanning ({len(tail)} - {tail_off})")
            return bytes(out_buf), info
        try:
            inline_len = struct.unpack_from("<I", tail, tail_off)[0]
            inline_body = tail[tail_off + 4:tail_off + 4 + inline_len]
            if inline_len == 0:
                info["inline_n_extents"] = 0
                return bytes(out_buf), info
            inline_shard = parse_shard(inline_body, spanning_blob_map=spanning_blob_map)
            apply_extents_from_shard(inline_shard)
            info["inline_used"] = True
            info["inline_n_extents"] = inline_shard.get("n_extents", 0)
            info["inline_consumed"] = inline_shard.get("bytes_consumed")
            info["inline_remaining"] = inline_shard.get("bytes_remaining")
            if inline_shard.get("bytes_remaining", 0) > 0:
                info["errors"].append(f"inline shard remaining {inline_shard['bytes_remaining']}")
        except Exception as e:
            info["errors"].append(f"inline shard parse: {e}")
        return bytes(out_buf), info

    # shards fetch (n_shards > 0)
    for shard_meta in on["extent_map_shards"]:
        shard_offset = shard_meta["offset"]
        shard_key = onode_key + struct.pack(">I", shard_offset) + b"x"
        shard_val = state.get(shard_key)
        if shard_val is None:
            info["shards_missing"] += 1
            info["errors"].append(f"shard offset=0x{shard_offset:x} not in state")
            continue
        info["shards_fetched"] += 1
        try:
            shard = parse_shard(shard_val, spanning_blob_map=spanning_blob_map)
        except Exception as e:
            info["errors"].append(f"shard parse offset=0x{shard_offset:x}: {e}")
            continue
        apply_extents_from_shard(shard)
    return bytes(out_buf), info


# 본 모듈은 step_i_union_5osd.py 가 사용하는 라이브러리이며 단독 실행 진입점은 두지 않는다.
# 회수 절차의 단일 진입점은 restore_vms.py (CLI) 이다.
