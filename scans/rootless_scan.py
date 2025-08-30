#!/usr/bin/env python3
"""
RootlessNetScan — async TCP-connect based port & host scanner (no root required).

Features:
 - Host discovery using TCP-connect on common ports (no raw sockets)
 - Async concurrent port scanning with asyncio
 - Simple banner grabbing
 - TLS certificate inspection for port 443
 - Reverse DNS lookup
 - JSON output report

IMPORTANT: Only scan networks you own or have explicit permission to test.
"""

import argparse
import asyncio
import socket
import ssl
import json
import ipaddress
from datetime import datetime

# Default ports used for discovery and quick scanning
COMMON_PORTS = [80, 443, 22, 21, 23, 25, 3389, 3306, 53, 139, 445]

SERVICE_NAMES = {
    80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 23: 'telnet', 25: 'smtp',
    3389: 'rdp', 3306: 'mysql', 53: 'dns', 139: 'netbios-ssn', 445: 'microsoft-ds'
}

async def try_connect(ip, port, timeout=1.0, banner_bytes=1024):
    """Attempt TCP connect & basic banner grab. Returns dictionary with result."""
    result = {'ip': str(ip), 'port': port, 'open': False, 'banner': None, 'service': SERVICE_NAMES.get(port)}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout=timeout)
        result['open'] = True

        # Try to read a small banner (non-blocking)
        try:
            data = await asyncio.wait_for(reader.read(banner_bytes), timeout=0.8)
            if data:
                try:
                    result['banner'] = data.decode(errors='ignore').strip()
                except Exception:
                    result['banner'] = repr(data[:200])
        except asyncio.TimeoutError:
            pass

        # TLS certificate inspection for port 443
        if port == 443:
            try:
                ctx = ssl.create_default_context()
                # do a short blocking socket connect to fetch cert (safer cross-platform)
                with socket.create_connection((str(ip), port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=None) as ss:
                        cert = ss.getpeercert()
                        result['tls_cert_subject'] = cert.get('subject') if cert else None
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass

    return result


async def scan_host_ports(ip, ports, semaphore, timeout):
    """Scan a set of ports for a single host using a semaphore to limit concurrency."""
    results = []

    async def _scan(p):
        async with semaphore:
            return await try_connect(ip, p, timeout=timeout)

    tasks = [asyncio.create_task(_scan(p)) for p in ports]
    for fut in asyncio.as_completed(tasks):
        r = await fut
        results.append(r)
    return results


async def discover_hosts(ips, discovery_ports, semaphore, timeout):
    """Return list of IPs that responded on any discovery port."""
    alive = []

    async def _probe(ip):
        for p in discovery_ports:
            async with semaphore:
                res = await try_connect(ip, p, timeout=timeout)
            if res['open']:
                return str(ip)
        return None

    tasks = [asyncio.create_task(_probe(ip)) for ip in ips]
    for fut in asyncio.as_completed(tasks):
        r = await fut
        if r:
            alive.append(r)
    return alive


def parse_ports(port_str):
    """Parse ports like '22,80,8000-8100' into a sorted list of ints."""
    ports = set()
    for part in str(port_str).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            for x in range(int(a), int(b) + 1):
                ports.add(int(x))
        else:
            ports.add(int(part))
    return sorted(ports)


def default_subnet_from_local():
    """Try to auto-detect local IP and return a /24 CIDR as default."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('1.1.1.1', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    parts = ip.split('.')
    parts[-1] = '0'
    return '.'.join(parts) + '/24'


def expand_targets(host=None, subnet=None, hosts_file=None):
    targets = []
    if host:
        targets.append(host)
    if subnet:
        net = ipaddress.ip_network(subnet, strict=False)
        for ip in net.hosts():
            targets.append(str(ip))
    if hosts_file:
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    # dedupe preserving order
    seen = set(); out = []
    for t in targets:
        if t not in seen:
            seen.add(t); out.append(t)
    return out


async def run_scan(targets, ports, concurrency, timeout, discovery_ports):
    sem = asyncio.Semaphore(concurrency)
    results = {'scan_time': datetime.utcnow().isoformat() + 'Z', 'hosts': []}

    # Discover alive hosts
    alive = await discover_hosts(targets, discovery_ports, sem, timeout)
    if not alive:
        return results

    for host in alive:
        host_info = {'ip': host, 'reverse_dns': None, 'ports': []}
        # reverse DNS
        try:
            host_info['reverse_dns'] = socket.gethostbyaddr(host)[0]
        except Exception:
            host_info['reverse_dns'] = None

        port_results = await scan_host_ports(host, ports, sem, timeout)
        open_ports = [p for p in port_results if p['open']]
        host_info['ports'] = open_ports
        results['hosts'].append(host_info)

    return results


def main():
    parser = argparse.ArgumentParser(description='RootlessNetScan - async TCP connect scanner (no root required)')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--host', help='Single host to scan (IP or hostname)')
    group.add_argument('--subnet', help='CIDR subnet to scan (e.g. 192.168.1.0/24)')
    parser.add_argument('--hosts-file', help='File with list of hosts (one per line)')
    parser.add_argument('--ports', default='1-1024', help='Comma separated ports or ranges, e.g. 22,80,1000-2000')
    parser.add_argument('--discovery-ports', default=','.join(map(str, COMMON_PORTS)), help='Ports used to decide if a host is alive (comma list)')
    parser.add_argument('--concurrency', type=int, default=200, help='Total concurrent connect attempts')
    parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout seconds')
    parser.add_argument('--output', default='scan_output.json', help='JSON output file')
    args = parser.parse_args()

    if not (args.host or args.subnet or args.hosts_file):
        print('[*] No target specified: auto-detecting local /24 as default.')
        args.subnet = default_subnet_from_local()

    targets = expand_targets(host=args.host, subnet=args.subnet, hosts_file=args.hosts_file)
    ports = parse_ports(args.ports)
    discovery_ports = parse_ports(args.discovery_ports)

    print(f'[*] Targets to consider: {len(targets)} addresses (discovery ports: {discovery_ports})')
    results = asyncio.run(run_scan(targets, ports, args.concurrency, args.timeout, discovery_ports))
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'[*] Scan finished. Results saved to {args.output}')


if __name__ == '__main__':
    main()
