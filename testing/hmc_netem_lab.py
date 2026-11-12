#!/usr/bin/env python3
"""Disposable Xray-only network impairment experiment; never run in the host netns."""
import argparse, concurrent.futures, copy, glob, hashlib, json, math, os, platform, random, secrets, shutil, signal, socket, statistics, struct, subprocess, sys, tempfile, threading, time, uuid
from pathlib import Path
import hmc_compare as base

HOST = '127.0.0.1'
SERVER = '10.203.77.2'
MODES = ['direct', 'vless-tls', 'reality-vision', 'hysteria2', 'hmc', 'vless-enc', 'hmc-enc', 'hmc-enc-mux']
CONDITIONS = {'C0': [], 'C1': ['delay', '10ms', '2ms'], 'C2': ['delay', '25ms', '5ms', 'loss', '1%'], 'C3': ['delay', '25ms', '5ms', 'loss', '3%']}
PADDING = '100-111-1111.0-0-0.50-0-3333'


def executable(name, optional=False):
    path = shutil.which(name)
    if not path:
        paths = glob.glob('/nix/store/*-' + name + '-*/bin/' + name)
        path = paths[0] if paths else None
    if not path and not optional:
        raise RuntimeError('missing executable: ' + name)
    return path


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def guard():
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('refusing: root in an isolated network namespace is required')
    links = json.loads(subprocess.check_output([executable('ip'), '-j', 'link'], text=True))
    if len(links) != 1 or links[0]['ifname'] != 'lo':
        raise RuntimeError('refusing: only loopback may exist initially')


def target(port):
    tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, port)); tcp.listen(128)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind((HOST, port))
    def connection(c):
        with c:
            try:
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while True:
                    data = c.recv(65536)
                    if not data: break
                    c.sendall(data)
            except OSError: pass
    def accept():
        while True:
            c, _ = tcp.accept(); threading.Thread(target=connection, args=(c,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    while True:
        data, addr = udp.recvfrom(65535); udp.sendto(data, addr)


def stats(values):
    if not values: return None
    v = sorted(values)
    return {'n': len(v), 'p50': statistics.median(v), 'p95': v[math.ceil(.95 * len(v))-1], 'min': v[0], 'max': v[-1]}


def cpu(p):
    try:
        v = Path('/proc/%d/stat' % p.pid).read_text().rsplit(')', 1)[1].split()
        return (int(v[11]) + int(v[12])) / os.sysconf('SC_CLK_TCK')
    except (OSError, AttributeError): return None


def bulk(proxy, target_port, size, streams):
    deadline = time.monotonic() + 60
    sockets = []; lock = threading.Lock(); count = [0]; errors = []
    barrier = threading.Barrier(streams + 1)
    def worker(i):
        s = None
        try:
            s = base.connect(proxy, target_port)
            with lock: sockets.append(s)
            s.settimeout(max(.01, deadline-time.monotonic()))
            base.exchange(s, struct.pack('!Q', i) + b'W'*56)
            payload = memoryview(struct.pack('!Q', i) + secrets.token_bytes(size-8))
            barrier.wait(timeout=max(.01, deadline-time.monotonic()))
            def recv():
                offset = 0
                try:
                    while offset < size:
                        s.settimeout(max(.01, deadline-time.monotonic()))
                        b = s.recv(min(65536, size-offset))
                        if not b: raise EOFError('bulk EOF')
                        if b != payload[offset:offset+len(b)]: raise ValueError('bulk exact-byte mismatch')
                        offset += len(b)
                        with lock: count[0] += len(b)
                except Exception as e:
                    with lock: errors.append(str(e))
            reader = threading.Thread(target=recv, daemon=True); reader.start()
            for offset in range(0, size, 65536):
                s.settimeout(max(.01, deadline-time.monotonic()))
                s.sendall(payload[offset:offset+65536])
            reader.join(max(0, deadline-time.monotonic()))
            if reader.is_alive(): raise TimeoutError('bulk receive deadline')
        except Exception as e:
            with lock: errors.append(type(e).__name__ + ': ' + str(e))
            try: barrier.abort()
            except Exception: pass
        finally:
            if s:
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                s.close()
    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in threads: t.start()
    started = time.monotonic()
    try:
        barrier.wait(timeout=max(.01, deadline-time.monotonic())); started = time.monotonic()
    except threading.BrokenBarrierError: errors.append('bulk setup failed or timed out')
    for t in threads: t.join(max(0, deadline-time.monotonic()))
    elapsed = time.monotonic()-started
    for s in sockets:
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
    for t in threads: t.join(1)
    if any(t.is_alive() for t in threads): errors.append('worker did not terminate')
    return {'status': 'PASS' if count[0] == size*streams and not errors else 'FAIL', 'verified_bytes': count[0], 'expected_bytes': size*streams, 'elapsed_s': elapsed, 'mib_s': count[0]/1048576/max(elapsed, .001), 'errors': errors}


def udp(proxy, port):
    ctl, relay = base.socks(proxy, 3, 0)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
    prefix = b'\0\0\0\x01'+socket.inet_aton(HOST)+struct.pack('!H', port)
    times = []; errors = []
    try:
        for i in range(41):
            body = struct.pack('!I', i) + b'U'*1196
            t = time.monotonic(); u.sendto(prefix+body, relay)
            end = t + (20 if i == 0 else 2)
            while time.monotonic() < end:
                u.settimeout(max(.001, end-time.monotonic()))
                try: data, _ = u.recvfrom(65535)
                except socket.timeout: break
                if data == prefix+body:
                    if i: times.append((time.monotonic()-t)*1000)
                    break
                errors.append('unexpected UDP datagram or exact-byte mismatch')
        return {'sent': 40, 'received': len(times), 'loss_percent': (40-len(times))*2.5, 'rtt_ms': stats(times), 'errors': errors}
    finally: u.close(); ctl.close()


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--namespace-isolated', action='store_true'); ap.add_argument('--binary', required=True); ap.add_argument('--output', required=True); ap.add_argument('--repeats', type=int, default=1); ap.add_argument('--target', type=int)
    args = ap.parse_args()
    if args.target is not None: target(args.target); return
    if not args.namespace_isolated: ap.error('pass --namespace-isolated inside a disposable netns')
    guard()
    if args.repeats < 1: ap.error('repeats must be positive')
    os.umask(0o077)
    ip, tc, nsenter, unshare = map(executable, ('ip', 'tc', 'nsenter', 'unshare'))
    openssl, ethtool = executable('openssl'), executable('ethtool', True)
    binary = str(Path(args.binary).resolve()); output = Path(args.output).resolve()
    report = {'binary': binary, 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'kernel': platform.uname()._asdict(), 'cpu': next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')), 'unknown'), 'python': platform.python_version(), 'conditions_one_way': CONDITIONS, 'repeats': args.repeats, 'seed': 1729, 'padding': PADDING, 'limits': 'Same-host veth; Python, CPU and kernel affect results. QUIC BBR vs TCP differ; do not generalize. Goodput counts unique verified echoed payload once. Bulk cap includes stream setup.', 'results': []}
    processes = []; peer = None
    def spawn(command, peer_side=False, log=None):
        if peer_side: command = [nsenter, '-t', str(peer.pid), '-n'] + command
        p = subprocess.Popen(command, stdout=log or subprocess.DEVNULL, stderr=log or subprocess.DEVNULL)
        processes.append(p); return p
    def peer_run(*cmd): run(nsenter, '-t', str(peer.pid), '-n', *cmd)
    def stop(p):
        if p is None: return
        if p.poll() is None: p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    def save():
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f: json.dump(report, f, indent=2); f.write('\n')
    try:
        with tempfile.TemporaryDirectory(prefix='hmc-netem-') as temp:
            root = Path(temp); os.chmod(root, 0o700)
            run(ip, 'link', 'set', 'lo', 'up')
            peer = spawn([unshare, '--net', 'sleep', '86400'])
            for _ in range(100):
                if os.readlink('/proc/%d/ns/net' % peer.pid) != os.readlink('/proc/self/ns/net'): break
                time.sleep(.01)
            else: raise RuntimeError('peer namespace did not start')
            run(ip, 'link', 'add', 'hmc-client', 'type', 'veth', 'peer', 'name', 'hmc-server')
            run(ip, 'link', 'set', 'hmc-server', 'netns', str(peer.pid))
            run(ip, 'addr', 'add', '10.203.77.1/30', 'dev', 'hmc-client'); run(ip, 'link', 'set', 'hmc-client', 'up')
            peer_run(ip, 'link', 'set', 'lo', 'up'); peer_run(ip, 'addr', 'add', SERVER+'/30', 'dev', 'hmc-server'); peer_run(ip, 'link', 'set', 'hmc-server', 'up')
            if ethtool:
                run(ethtool, '-K', 'hmc-client', 'gro', 'off', 'gso', 'off', 'tso', 'off'); peer_run(ethtool, '-K', 'hmc-server', 'gro', 'off', 'gso', 'off', 'tso', 'off')
            report['offload_disabled'] = bool(ethtool)
            cert = root/'cert'; uid = str(uuid.uuid4()); password = secrets.token_urlsafe(48)
            subprocess.run([binary, 'tls', 'cert', '--ca', '--domain', 'localhost', '--file', str(cert)], check=True, stdout=subprocess.DEVNULL)
            venc = [l.split('"')[3] for l in subprocess.check_output([binary, 'vlessenc'], text=True).splitlines() if l.startswith(('"decryption"', '"encryption"'))]
            keys = dict(line.split(': ',1) for line in subprocess.check_output([binary, 'x25519'], text=True).splitlines() if ': ' in line)
            def padding(v):
                parts = v.split('.'); return '.'.join(parts[:3]+[PADDING]+parts[3:])
            keys['venc_dec'], keys['venc_enc'] = map(padding, venc[:2])
            target_port = 39001; fb = 39002; sp = 39003
            spawn([sys.executable, str(Path(__file__).resolve()), '--binary', binary, '--output', str(output), '--target', str(target_port)], True)
            spawn([openssl, 's_server', '-accept', f'{HOST}:{fb}', '-cert', str(cert)+'.crt', '-key', str(cert)+'.key', '-tls1_3', '-alpn', 'h2', '-www'], True)
            time.sleep(.3)
            for condition, setting in CONDITIONS.items():
                for dev, inside in [('hmc-client', False), ('hmc-server', True)]:
                    cmd = [tc, 'qdisc', 'replace', 'dev', dev, 'root', 'netem'] + setting
                    if inside: peer_run(*cmd)
                    else: run(*cmd)
                for repeat in range(args.repeats):
                    modes = MODES[:]; random.Random(1729+repeat+list(CONDITIONS).index(condition)*100).shuffle(modes)
                    for mode in modes:
                        row = {'condition': condition, 'mode': mode, 'repeat': repeat, 'errors': [], 'status': 'FAIL'}; server = client = None; before = None
                        try:
                            proxy = base.port()
                            if mode == 'direct':
                                sc = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': SERVER, 'port': sp, 'protocol': 'dokodemo-door', 'settings': {'address': HOST, 'port': target_port, 'network': 'tcp,udp'}}], 'outbounds': [{'protocol': 'freedom'}]}
                                cc = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': HOST, 'port': proxy, 'protocol': 'socks', 'settings': {'udp': True}}], 'outbounds': [{'protocol': 'freedom', 'settings': {'redirect': SERVER+':'+str(sp)}}]}
                            else:
                                sc, cc = base.configs(mode, sp, proxy, cert, uid, password, keys, fb)
                                sc['inbounds'][0]['listen'] = SERVER
                                outbound = cc['outbounds'][0]['settings']
                                if mode == 'hysteria2': outbound['address'] = SERVER
                                else: outbound['vnext'][0]['address'] = SERVER
                            server_cfg = root/'server.json'; client_cfg = root/'client.json'
                            server_cfg.write_text(json.dumps(sc)); client_cfg.write_text(json.dumps(cc))
                            logpath = root/'run.log'; log = logpath.open('wb')
                            server = spawn([binary, 'run', '-config', str(server_cfg)], True, log)
                            time.sleep(.4)
                            client = spawn([binary, 'run', '-config', str(client_cfg)], False, log); log.close()
                            base.ready(client, proxy)
                            before = {'client': cpu(client), 'server': cpu(server)}
                            start = time.monotonic()
                            def cold_timeout(signum, frame): raise TimeoutError('cold echo exceeded 20 seconds')
                            previous = signal.signal(signal.SIGALRM, cold_timeout)
                            signal.setitimer(signal.ITIMER_REAL, 20)
                            try:
                                sock = base.connect(proxy, target_port)
                                try: base.exchange(sock, b'C'*64)
                                except BaseException:
                                    sock.close(); raise
                            finally:
                                signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
                            with sock:
                                row['cold_ms'] = (time.monotonic()-start)*1000
                                warm = []
                                for i in range(40):
                                    start = time.monotonic(); base.exchange(sock, struct.pack('!I',i)+b'W'*60); warm.append((time.monotonic()-start)*1000)
                                row['warm_ms'] = stats(warm)
                            row['bulk_1'] = bulk(proxy, target_port, 8*1024*1024, 1)
                            row['bulk_8'] = bulk(proxy, target_port, 4*1024*1024, 8)
                            try: row['udp'] = udp(proxy, target_port)
                            except Exception as e: row['udp'] = {'error': type(e).__name__+': '+str(e)}
                            row['cpu_seconds'] = {name: (cpu(p)-before[name]) if before[name] is not None and cpu(p) is not None else None for name, p in [('client', client), ('server', server)]}
                            row['status'] = 'PASS' if row['bulk_1']['status'] == row['bulk_8']['status'] == 'PASS' and not row['udp'].get('errors') and 'error' not in row['udp'] else 'FAIL'
                        except Exception as e: row['errors'].append(type(e).__name__+': '+str(e))
                        finally:
                            if before and 'cpu_seconds' not in row:
                                row['cpu_seconds'] = {name: (cpu(p)-before[name]) if before[name] is not None and cpu(p) is not None else None for name, p in [('client', client), ('server', server)]}
                            stop(client); stop(server)
                            if (root/'run.log').exists():
                                lines = (root/'run.log').read_text(errors='replace').splitlines()
                                row['log_error_count'] = sum('error' in line.lower() or 'failed' in line.lower() for line in lines)
                            report['results'].append(row); save()
                            print(json.dumps(row), flush=True)
    finally:
        for p in reversed(processes): stop(p)
        subprocess.run([ip, 'link', 'del', 'hmc-client'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('\nCondition / mode | cold ms median [range] | warm p50 ms | 1/8-stream MiB/s | UDP loss % | failures')
    for cond in CONDITIONS:
        for mode in MODES:
            rows = [r for r in report['results'] if r['condition'] == cond and r['mode'] == mode]
            def val(key):
                x = [key(r) for r in rows]; x = [v for v in x if v is not None]
                return ('%.2f [%.2f–%.2f]' % (statistics.median(x), min(x), max(x))) if x else 'n/a'
            print(cond, mode, '|', val(lambda r:r.get('cold_ms')), '|', val(lambda r:(r.get('warm_ms') or {}).get('p50')), '|', val(lambda r:(r.get('bulk_1') or {}).get('mib_s')), '/', val(lambda r:(r.get('bulk_8') or {}).get('mib_s')), '|', val(lambda r:(r.get('udp') or {}).get('loss_percent')), '|', sum(r['status'] != 'PASS' for r in rows), '/', len(rows))
    return 0

if __name__ == '__main__': raise SystemExit(main())
