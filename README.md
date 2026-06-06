# proxmox-ceph-restore-vm

A tool that recovers RBD virtual machine disks from inactive Proxmox-Ceph OSD raw images.

Taking only the raw images of OSD disks as input — without an active Ceph cluster or any external tool to mount the disks — it reassembles RBD virtual machine disks byte-for-byte based on BlueStore's disk-write specification.

This tool provides, as a single CLI, the recovery procedure from the master's thesis *"Recovering Data from Distributed Object Storage in an Inactive State — Focused on the Proxmox-Ceph Environment"* (Donghyun Seok, Department of Forensic Science, Graduate School, Sungkyunkwan University, 2026). It was validated on Proxmox VE 8, Ceph Reef 18.2.8, and replication policy size=3. Across three datasets configured with 3, 4, and 5 OSDs, for all 12 virtual machines the SHA-256 of the recovered result matched the SHA-256 of the original `rbd export`.

---

## Dependencies

- Python 3.11 or later
- `pip install -r requirements.txt` (rocksdict)

---

## Usage

```bash
python restore_vms.py --osd-dir /path/to/osd/raw/images --output /path/to/output
```

- `--osd-dir` : Directory containing the OSD raw images. `*.001`, `*.raw`, and `*.img` files are auto-discovered.
- `--output` : Output directory for the recovery results. Created automatically.

To recover a specific virtual machine only, pass its `image_id`:

```bash
python restore_vms.py --osd-dir ./osds --output ./recovered --image-id fbabeb6914038
```

---

## Console output

While running, the tool shows the progress of the five stages and, at the end, prints three tables that the analyst can copy directly into a report.

- Table 1 — OSD identification: OSD raw, ceph_fsid, osd_uuid, whoami, status
- Table 2 — Recovered virtual machines: image_id, vm_name, image_size, SHA-256
- Table 3 — Deleted virtual machine residue: image_id, rbd_header, chunk-trace OSD, trace chunks, residual chunks

Recovered virtual machine disks are saved to `<output>/_i_results/*_union.raw`. Detailed per-stage logs are written to `<output>/restore_vms.log`.

---

## License

MIT License. See the `LICENSE` file.
