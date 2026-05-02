"""
Merge all cve_raw JSON files in the repository root into a single kev_raw.json
This is a convenience script to produce a large `kev_raw.json` for downstream
processing when the official CISA KEV feed is much smaller than NVD CVE data.

It will back up any existing `kev_raw.json` to `kev_raw.cisa_backup.json` before
overwriting.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERN = "cve_raw*.json"


def main():
    files = sorted(ROOT.glob(PATTERN))

    if not files:
        print("No cve_raw JSON files found to merge.")
        return 1

    all_records = []

    for f in files:
        try:
            with f.open("r", encoding="utf-8") as fh:
                data = json.load(fh)

            if isinstance(data, dict):
                # some cve files may be an object with 'CVE_Items' or similar
                # try to extract common arrays
                if "CVE_Items" in data:
                    items = data.get("CVE_Items", [])
                else:
                    # if top-level dict with numeric keys or 'data'
                    items = []
                    for v in data.values():
                        if isinstance(v, list):
                            items = v
                            break
                all_records.extend(items)

            elif isinstance(data, list):
                all_records.extend(data)

            else:
                print(f"Skipping {f.name}: unexpected JSON type {type(data)}")

            print(f"Loaded {f.name}: {len(data) if isinstance(data, (list, dict)) else 0} entries")

        except Exception as exc:
            print(f"Failed to load {f}: {exc}")

    kev_path = ROOT / "kev_raw.json"
    backup_path = ROOT / "kev_raw.cisa_backup.json"

    if kev_path.exists():
        kev_path.replace(backup_path)
        print(f"Existing kev_raw.json backed up to {backup_path.name}")

    # write combined list
    with kev_path.open("w", encoding="utf-8") as out:
        json.dump(all_records, out, indent=2)

    print(f"Wrote {len(all_records):,} records to {kev_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
