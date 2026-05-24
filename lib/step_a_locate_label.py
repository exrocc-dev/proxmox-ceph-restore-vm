"""
단계 A — BlueStore label magic 위치 확인

목적: osd3 의 3 raw 가 PV 전체 dump 인지 LV-only dump 인지 결정론적 분류.
방법: 각 raw 의 첫 1 MiB + 1 KiB 만 read-only 로 열고
      ASCII magic "bluestore block device\n" (23 byte) 의 offset grep.

R8: read-only `open(..., 'rb')` + read. 그 외 작업 없음.
근거: 06.md §1.2 / bluestore_types.cc::bluestore_bdev_label_t::encode
      magic = b"bluestore block device\n"
"""
from pathlib import Path

MAGIC = b"bluestore block device\n"
SEARCH_BYTES = 1024 * 1024 + 4096   # 첫 1 MiB + 4 KiB (PV-relative 0x100000 + label 4 KiB)

OSD3_DIR = Path(r"D:\성대 논문\osd3")
RAWS = ["pve.001", "pve2.001", "pve3.001"]

def find_magic_offsets(path: Path, search_bytes: int) -> list[int]:
    """첫 search_bytes 만 read 하여 magic 의 모든 offset 반환."""
    offsets = []
    with open(path, "rb") as f:
        buf = f.read(search_bytes)
    pos = 0
    while True:
        idx = buf.find(MAGIC, pos)
        if idx < 0:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def classify_layout(offsets: list[int]) -> str:
    """offset 분포로 layout 분류."""
    if not offsets:
        return "NO_MAGIC_FOUND (within first 1 MiB + 4 KiB)"
    if 0x100000 in offsets:
        return "PV-FULL-DUMP (LVM PV with PE start at 0x100000)"
    if 0 in offsets:
        return "LV-ONLY-DUMP (logical volume only)"
    return f"UNKNOWN (magic at unexpected offset(s): {[hex(o) for o in offsets]})"


def main():
    print("=" * 72)
    print("단계 A — BlueStore label magic 위치 분류")
    print(f"MAGIC pattern: {MAGIC!r} ({len(MAGIC)} byte)")
    print(f"Search range:  first {SEARCH_BYTES} byte ({SEARCH_BYTES / 1024:.0f} KiB)")
    print("=" * 72)

    results = {}
    for raw_name in RAWS:
        path = OSD3_DIR / raw_name
        if not path.exists():
            print(f"\n{raw_name}: FILE NOT FOUND at {path}")
            continue
        size = path.stat().st_size
        offsets = find_magic_offsets(path, SEARCH_BYTES)
        layout = classify_layout(offsets)
        print(f"\n{raw_name} ({size:,} byte = {size / 1024**3:.2f} GiB):")
        print(f"  magic offsets: {[hex(o) for o in offsets] if offsets else '(none)'}")
        print(f"  layout:        {layout}")
        results[raw_name] = {"offsets": offsets, "layout": layout, "size": size}

    print()
    print("=" * 72)
    print("CROSS-CHECK")
    print("=" * 72)
    layouts = set(r["layout"] for r in results.values())
    if len(layouts) == 1:
        print(f"All 3 OSDs same layout: {layouts.pop()}  ← consistent")
    else:
        print(f"INCONSISTENT layouts across OSDs: {layouts}")
        print("  → 추가 분석 필요")


if __name__ == "__main__":
    main()
