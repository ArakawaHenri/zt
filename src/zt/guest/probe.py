#!/usr/bin/env python3
"""In-container network reachability probe and ZT-INPUT control toggle.

Used during image verification from a second peer container (`probe`, `setup-ipv6`)
and inside the target container (`toggle out|in <net_mode>`).
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


def probe_udp(address, port, timeout=2.0):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b'zt', (address, port))
            return 'through' if sock.recvfrom(64)[0] == b'pong:zt' else 'stopped'
    except OSError:
        return 'stopped'


def cmd_probe(ipv4, ipv6, port):
    questions = [
        ('desktop over IPv4', probe_tcp, ipv4, 6901),
        ('stand-in over IPv4', probe_tcp, ipv4, port),
        ('stand-in UDP over IPv4', probe_udp, ipv4, port),
    ]
    if ipv6:
        questions.append(('stand-in over IPv6', probe_tcp, ipv6, port))
        questions.append(('stand-in UDP over IPv6', probe_udp, ipv6, port))
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(questions)) as pool:
        futs = [(label, pool.submit(fn, addr, to)) for label, fn, addr, to in questions]
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

    subnet = link_subnet(wan) if net_mode == 'subnet' else ''
    if net_mode == 'subnet' and not subnet:
        print(f'no link-scope subnet on {wan}', file=sys.stderr)
        sys.exit(1)

    cmds = []
    for proto, comment in (('tcp', 'zt: host only'), ('udp', 'zt: host only udp')):
        v4_cmd = ['iptables', '-t', 'filter', '-D', 'ZT-INPUT', '-i', wan]
        if net_mode == 'subnet':
            v4_cmd += ['-s', subnet]
        v4_cmd += ['-p', proto, '-m', 'comment', '--comment', comment, '-j', 'DROP']
        v6_cmd = [
            'ip6tables', '-t', 'filter', '-D', 'ZT-INPUT', '-i', wan,
            '-p', proto, '-m', 'comment', '--comment', comment, '-j', 'DROP',
        ]
        cmds.extend((v4_cmd, v6_cmd))

    for cmd in cmds:
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
