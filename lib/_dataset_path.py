"""
_dataset_path.py — OSD raw 이미지와 출력 디렉터리 경로 결정.

본 모듈은 step_a ~ step_i 단계 도구가 공통으로 import 한다.
경로는 환경변수로 결정되며, 기본 동작은 다음과 같다.

  - OSD_RAW_DIR  : OSD raw 이미지가 위치한 디렉터리 (필수)
  - OUTPUT_DIR   : 회수 결과를 저장할 디렉터리 (필수)
  - OSD_GLOB     : OSD raw 파일을 찾을 glob 패턴 (선택, 기본 *.001;*.raw;*.img)

restore_vms.py CLI 가 위 환경변수를 설정한 뒤 step 모듈들을 호출한다.
사용자가 step 모듈을 직접 실행하려면 환경변수를 미리 설정해야 한다.

PowerShell:
  $env:OSD_RAW_DIR = "C:\\path\\to\\osd\\images"
  $env:OUTPUT_DIR  = "C:\\path\\to\\output"
  python lib\\step_b_decode_label.py

bash:
  export OSD_RAW_DIR=/path/to/osd/images
  export OUTPUT_DIR=/path/to/output
  python lib/step_b_decode_label.py
"""
import os
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

# ─── 환경변수에서 경로 읽기 ───
_raw_dir_env = os.environ.get("OSD_RAW_DIR")
_output_env = os.environ.get("OUTPUT_DIR")

if not _raw_dir_env:
    raise RuntimeError(
        "환경변수 OSD_RAW_DIR 이 설정되지 않았다. OSD raw 이미지가 든 디렉터리를 "
        "지정해야 한다. restore_vms.py CLI 를 사용하면 자동 설정된다."
    )
if not _output_env:
    raise RuntimeError(
        "환경변수 OUTPUT_DIR 이 설정되지 않았다. 회수 결과를 저장할 디렉터리를 "
        "지정해야 한다. restore_vms.py CLI 를 사용하면 자동 설정된다."
    )

RAW_DIR = Path(_raw_dir_env)
EXTRACTED_BASE = Path(_output_env)


# ─── OSD raw 파일 자동 발견 ───
def _build_osd_raw() -> dict[str, Path]:
    """RAW_DIR 안의 OSD raw 이미지 파일을 발견하여 osd.N → 경로 매핑을 반환.

    매칭 규칙: OSD_GLOB 환경변수로 지정한 glob 패턴 (세미콜론 구분, 기본
    '*.001;*.raw;*.img'). 알파벳 순으로 정렬하여 osd.0, osd.1, ... 번호 부여.

    실제 OSD 번호 (whoami) 는 BlueStore Label 디코딩 (단계 B) 이후 확인되며,
    파일명 순서와 다를 수 있다. restore_vms.py 는 단계 B 결과로 매핑을
    재구성한다.
    """
    out: dict[str, Path] = {}
    if not RAW_DIR.exists():
        return out

    patterns_raw = os.environ.get("OSD_GLOB", "*.001;*.raw;*.img")
    patterns = [p.strip() for p in patterns_raw.split(";") if p.strip()]

    candidates: set[Path] = set()
    for pattern in patterns:
        for p in RAW_DIR.glob(pattern):
            if p.is_file():
                candidates.add(p)

    for i, p in enumerate(sorted(candidates, key=lambda x: x.name)):
        out[f"osd.{i}"] = p
    return out


OSD_RAW = _build_osd_raw()
OSDS = sorted(OSD_RAW.keys()) if OSD_RAW else []
