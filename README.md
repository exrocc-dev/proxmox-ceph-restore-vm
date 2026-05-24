# proxmox-ceph-restore-vm

비활성 Proxmox-Ceph OSD raw 이미지로부터 RBD 가상머신 디스크를 회수하는 도구.

활성 Ceph 클러스터의 동작이나 외부 도구의 mount 없이 OSD 디스크의 raw 이미지만을 입력으로 받아, BlueStore 의 디스크 기록 사양에 근거하여 RBD 가상머신 디스크를 byte 단위로 재조립한다.

본 도구는 학위논문 *"비활성 상태에서의 분산 객체 스토리지 데이터 회수 방안 — Proxmox-Ceph 환경을 중심으로"* (석동현, 성균관대학교 일반대학원 과학수사학과, 2026) 의 회수 절차를 단일 CLI 로 제공한다. 검증 환경은 Proxmox VE 8 · Ceph Reef 18.2.8 · 복제 정책 size=3 이며, OSD 3·4·5 개로 구성한 세 데이터셋의 11 개 가상머신에 대하여 회수 결과 SHA-256 이 원본 `rbd export` 의 SHA-256 과 일치함을 확인하였다.

---

## 의존성

- Python 3.11 이상
- `pip install -r requirements.txt` (rocksdict)

---

## 사용법

```bash
python restore_vms.py --osd-dir /path/to/osd/raw/images --output /path/to/output
```

- `--osd-dir` : OSD raw 이미지가 들어 있는 디렉터리. `*.001`, `*.raw`, `*.img` 파일을 자동 발견한다.
- `--output` : 회수 결과 출력 디렉터리. 자동 생성된다.

---

## 화면 출력

회수 절차를 진행하면서 5 단계 진행 상황을 표시하고, 마지막에 분석자 보고서에 그대로 옮길 수 있는 세 표를 출력한다.

- 표 1 OSD 식별 — OSD raw · ceph_fsid · osd_uuid · whoami · 상태
- 표 2 회수된 가상머신 — image_id · vm_name · image_size · SHA-256
- 표 3 삭제된 가상머신 잔재 — image_id · rbd_header · chunk 흔적 OSD · 흔적 chunk · 잔존 chunk

회수된 가상머신 디스크는 `<output>/_i_results/*_union.raw` 에 저장된다. 단계별 상세 로그는 `<output>/restore_vms.log` 에 기록된다.

---

## 학술 인용

> 석동현, "비활성 상태에서의 분산 객체 스토리지 데이터 회수 방안 — Proxmox-Ceph 환경을 중심으로," 성균관대학교 일반대학원 과학수사학과 석사학위논문, 2026.

---

## 라이선스

MIT License. `LICENSE` 파일 참조.
