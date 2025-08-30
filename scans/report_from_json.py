#!/usr/bin/env python3
"""
Simple HTML report generator for RootlessNetScan JSON output.

Usage:
  python scans/report_from_json.py scan_output.json report.html
"""
import sys, json, html

if len(sys.argv) < 3:
    print('Usage: report_from_json.py input.json output.html')
    sys.exit(1)

infile, outfile = sys.argv[1], sys.argv[2]
with open(infile, 'r') as f:
    data = json.load(f)

html_parts = [
    '<!doctype html>',
    '<html><head><meta charset="utf-8"><title>RootlessNetScan Report</title>',
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">',
    '<style>',
    'body{font-family:Inter,Arial,Helvetica,sans-serif;background:#071030;color:#e6eef8;padding:18px}',
    '.card{background:#0f172a;padding:12px;border-radius:8px;margin-bottom:10px}',
    'h1,h2{margin:6px 0}',
    'pre{white-space:pre-wrap;background:#071425;padding:8px;border-radius:6px}',
    '</style></head><body>'
]

html_parts.append(f"<h1>RootlessNetScan Report</h1><p>Scan time: {html.escape(str(data.get('scan_time','')))}</p>")

for host in data.get('hosts', []):
    ip = html.escape(host.get('ip', ''))
    rdns = html.escape(str(host.get('reverse_dns', '') or ''))
    html_parts.append('<div class="card">')
    html_parts.append(f'<h2>{ip} {(" — " + rdns) if rdns else ""}</h2>')
    ports = host.get('ports', [])
    if ports:
        html_parts.append('<ul>')
        for p in ports:
            portnum = p.get('port')
            svc = html.escape(str(p.get('service') or ''))
            banner = html.escape(str(p.get('banner') or ''))
            tls = html.escape(str(p.get('tls_cert_subject') or ''))
            html_parts.append(f'<li><strong>{portnum}</strong> {svc}<br/><pre>{banner}</pre>')
            if tls:
                html_parts.append(f'<div>TLS cert subject: <pre>{tls}</pre></div>')
            html_parts.append('</li>')
        html_parts.append('</ul>')
    else:
        html_parts.append('<p>No open ports found.</p>')
    html_parts.append('</div>')

html_parts.append('</body></html>')

with open(outfile, 'w', encoding='utf-8') as f:
    f.write('\n'.join(html_parts))

print('Report written to', outfile)
