#!/usr/bin/env python3
"""In-container network reachability probe and ZT-INPUT control toggle.

Used during `zt verify` from a second peer container (`probe`, `setup-ipv6`) and
inside the target container (`toggle out|in <net_mode>`).
"""
import concurrent.futures
import errno
import json
import os
import socket
import subprocess
import sys


def default_wan():
    proc = subprocess.run(
        ['ip', '-4', 'route', 'show', 'default'],
        capture_output=True, text=True, check=False,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] == 'via':
            return parts[4]
    return ''


def link_subnet(wan):
    proc = subprocess.run(
        ['ip', '-4', 'route', 'show', 'dev', wan, 'scope', 'link'],
        capture_output=True, text=True, check=False,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts:
            return parts[0]
    return ''


def probe_tcp(address, port, timeout=4.0):
    try:
        socket.create_connection((address, port), timeout=timeout).close()
        return 'through'
    except OSError as error:
        return 'refused' if error.errno == errno.ECONNREFUSED else 'stopped'


def cmd_probe(ipv4, ipv6, port):
    questions = [
        ('desktop over IPv4', ipv4, 6901),
        ('stand-in over IPv4', ipv4, port),
    ]
    if ipv6:
        questions.append(('stand-in over IPv6', ipv6, port))
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(questions)) as pool:
        futs = [(label, pool.submit(probe_tcp, addr, to)) for label, addr, to in questions]
        answers = {label: fut.result() for label, fut in futs}
    print(json.dumps(answers, sort_keys=True))


def cmd_setup_ipv6(cidr):
    wan = default_wan() or 'eth0'
    proc = subprocess.run(['ip', 'addr', 'add', cidr, 'dev', wan, 'nodad'], check=False)
    sys.exit(proc.returncode)


def cmd_toggle(direction, net_mode):
    if direction == 'in':
        env = dict(os.environ, ZT_NET_MODE=net_mode)
        proc = subprocess.run(['/usr/local/bin/zt-net-setup.sh'], env=env, check=False)
        sys.exit(proc.returncode)

    wan = default_wan()
    if not wan:
        print('no default route', file=sys.stderr)
        sys.exit(1)

    v4_cmd = ['iptables', '-t', 'filter', '-D', 'ZT-INPUT', '-i', wan]
    if net_mode == 'subnet':
        subnet = link_subnet(wan)
        if not subnet:
            print(f'no link-scope subnet on {wan}', file=sys.stderr)
            sys.exit(1)
        v4_cmd += ['-s', subnet]
    v4_cmd += ['-p', 'tcp', '-m', 'comment', '--comment', 'zt: host only', '-j', 'DROP']

    v6_cmd = [
        'ip6tables', '-t', 'filter', '-D', 'ZT-INPUT', '-i', wan,
        '-p', 'tcp', '-m', 'comment', '--comment', 'zt: host only', '-j', 'DROP',
    ]
    for cmd in (v4_cmd, v6_cmd):
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            sys.exit(proc.returncode)


def main():
    action = sys.argv[1]
    if action == 'probe':
        cmd_probe(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif action == 'setup-ipv6':
        cmd_setup_ipv6(sys.argv[2])
    elif action == 'toggle':
        cmd_toggle(sys.argv[2], sys.argv[3])
    else:
        sys.exit(f'unknown action: {action}')


if __name__ == '__main__':
    main()
