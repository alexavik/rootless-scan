#!/usr/bin/env bash
# Small safe example that scans your localhost (no network harm).
python3 scans/rootless_scan.py --host 127.0.0.1 --ports 22,80,443 --output out_local.json
python3 scans/report_from_json.py out_local.json out_local.html
echo "Done. Check out out_local.json and out_local.html"
