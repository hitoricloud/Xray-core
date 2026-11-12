#!/usr/bin/env python3
"""Local-only synthetic Xray comparison; no external addresses or trust bypass."""
import argparse, collections, concurrent.futures, copy, hashlib, json, os, platform, random, secrets, socket, struct, subprocess, tempfile, threading, time, uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent
HOST='127.0.0.1'
MODES=['direct','hmc','vless-tls','reality-vision','hysteria2','hmc-mux','vless-tls-mux','vless-enc','hmc-enc','vless-enc-mux','hmc-enc-mux']

def port():
    with socket.socket() as s:
        s.bind((HOST,0)); return s.getsockname()[1]
def exact(s,n):
    b=bytearray()
    while len(b)<n:
        v=s.recv(n-len(b))
        if not v: raise EOFError('unexpected EOF')
        b.extend(v)
    return bytes(b)
def socks(p,cmd,dest):
    s=socket.create_connection((HOST,p),timeout=20); s.settimeout(20); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    try:
        s.sendall(b'\x05\x01\x00')
        if exact(s,2)!=b'\x05\x00': raise ValueError('SOCKS authentication')
        s.sendall(b'\x05'+bytes([cmd])+b'\x00\x01'+socket.inet_aton(HOST)+struct.pack('!H',dest))
        h=exact(s,4)
        if h[:2]!=b'\x05\x00' or h[3]!=1: raise ValueError('SOCKS reply '+h.hex())
        ip=socket.inet_ntoa(exact(s,4)); q=struct.unpack('!H',exact(s,2))[0]
        return s,(HOST if ip=='0.0.0.0' else ip,q)
    except BaseException:
        s.close(); raise

def targets():
    tcp=socket.socket(); tcp.bind((HOST,0)); tcp.listen(64); tcp.settimeout(.2)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind((HOST,0)); udp.settimeout(.2)
    stop=threading.Event()
    def handle(c):
        with c:
            c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            try:
                while True:
                    b=c.recv(65536)
                    if not b: break
                    c.sendall(b)
            except OSError: pass
    def accept():
        while not stop.is_set():
            try: c,_=tcp.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
            except socket.timeout: pass
            except OSError: break
    def datagrams():
        while not stop.is_set():
            try: b,a=udp.recvfrom(65535); udp.sendto(b,a)
            except socket.timeout: pass
            except OSError: break
    for f in (accept,datagrams): threading.Thread(target=f,daemon=True).start()
    return tcp,udp,stop

def delay_proxy(target_port,one_way_ms):
    # TCP-only fixed one-way delay; the TCP handshake itself is not delayed.
    listener=socket.socket(); listener.bind((HOST,0)); listener.listen(64)
    stop=threading.Event()
    def pump(src,dst):
        queue=collections.deque(); cv=threading.Condition(); done=[False]
        def reader():
            try:
                while True:
                    data=src.recv(65536)
                    if not data: break
                    with cv: queue.append((time.monotonic()+one_way_ms/1000,data)); cv.notify()
            except OSError: pass
            with cv: done[0]=True; cv.notify()
        def writer():
            try:
                while True:
                    with cv:
                        while not queue and not done[0]: cv.wait()
                        if not queue: break
                        due,data=queue.popleft()
                    wait=due-time.monotonic()
                    if wait>0: time.sleep(wait)
                    dst.sendall(data)
            except OSError: pass
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass
        threading.Thread(target=reader,daemon=True).start(); threading.Thread(target=writer,daemon=True).start()
    def accept():
        while not stop.is_set():
            try: c,_=listener.accept()
            except OSError: break
            s=socket.create_connection((HOST,target_port))
            for x in (c,s): x.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            pump(c,s); pump(s,c)
    threading.Thread(target=accept,daemon=True).start()
    return listener.getsockname()[1],(stop,listener)

def configs(mode,server_port,client_port,cert,uid,password,keys,fb):
    mux=mode.endswith('-mux'); mode=mode.removesuffix('-mux')
    tls_server={'certificates':[{'certificateFile':str(cert)+'.crt','keyFile':str(cert)+'.key'}]}
    tls_client={'serverName':'localhost','disableSystemRoot':True,'certificates':[{'certificateFile':str(cert)+'.crt','usage':'verify'}]}
    ss={'network':'raw','security':'tls','tlsSettings':tls_server}; cs={'network':'raw','security':'tls','tlsSettings':tls_client}
    user={'id':uid}; remote={'id':uid,'encryption':'none'}; decryption='none'
    if mode in ('vless-enc','hmc-enc'):
        # VLESS Encryption replaces the inner TLS: no certificates, pinned server key.
        ss={'network':'raw'}; cs={'network':'raw'}; decryption=keys['venc_dec']; remote['encryption']=keys['venc_enc']
    if mode in ('hmc','hmc-enc'):
        mask={'tcp':[{'type':'hmc','settings':{'password':password,'hostname':'localhost','profiles':[{'username':'TestUser','uuid':uid}]}}]}
        ss['finalmask']=copy.deepcopy(mask); cs['finalmask']=copy.deepcopy(mask)
        del ss['finalmask']['tcp'][0]['settings']['profiles']
    if mode=='reality-vision':
        user['flow']=remote['flow']='xtls-rprx-vision'
        ss={'network':'raw','security':'reality','realitySettings':{'dest':f'{HOST}:{fb}','serverNames':['localhost'],'privateKey':keys['PrivateKey'],'shortIds':['1234abcd']}}
        cs={'network':'raw','security':'reality','realitySettings':{'serverName':'localhost','fingerprint':'chrome','password':keys['Password (PublicKey)'],'shortId':'1234abcd'}}
    if mode=='hysteria2':
        ss={'network':'hysteria','security':'tls','tlsSettings':tls_server,'hysteriaSettings':{'version':2},'finalmask':{'quicParams':{'congestion':'bbr'}}}
        cs={'network':'hysteria','security':'tls','tlsSettings':tls_client,'hysteriaSettings':{'version':2,'auth':password},'finalmask':{'quicParams':{'congestion':'bbr'}}}
        inbound={'listen':HOST,'port':server_port,'protocol':'hysteria','settings':{'version':2,'users':[{'auth':password}]},'streamSettings':ss}
        outbound={'protocol':'hysteria','settings':{'version':2,'address':HOST,'port':server_port},'streamSettings':cs}
    else:
        inbound={'listen':HOST,'port':server_port,'protocol':'vless','settings':{'clients':[user],'decryption':decryption},'streamSettings':ss}
        outbound={'protocol':'vless','settings':{'vnext':[{'address':HOST,'port':server_port,'users':[remote]}]},'streamSettings':cs}
    server={'log':{'loglevel':'warning'},'inbounds':[inbound],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','network':'tcp,udp','ip':['127.0.0.1/32']}]}}]}
    client={'log':{'loglevel':'warning'},'inbounds':[{'listen':HOST,'port':client_port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],'outbounds':[outbound]}
    if mux: client['outbounds'][0]['mux']={'enabled':True,'concurrency':8,'xudpConcurrency':16}
    return server,client

def proc_stats(p):
    if p is None: return None
    stat=Path(f'/proc/{p.pid}/stat').read_text(); v=stat[stat.rfind(')')+2:].split()
    mem={}
    for line in Path(f'/proc/{p.pid}/smaps_rollup').read_text().splitlines():
        if line.startswith(('Rss:','Pss:')):
            k,x,*_=line.split(); mem[k[:-1]+'_kib']=int(x)
    return {'cpu_seconds':(int(v[11])+int(v[12]))/os.sysconf('SC_CLK_TCK'),**mem}

def start(binary,cfg,path,log):
    path.write_text(json.dumps(cfg)); f=log.open('ab'); p=subprocess.Popen([binary,'run','-config',str(path)],stdout=f,stderr=subprocess.STDOUT); f.close(); return p

def ready(p,port):
    end=time.monotonic()+10
    while time.monotonic()<end:
        if p.poll() is not None: raise RuntimeError('core exited; inspect log')
        try:
            with socket.create_connection((HOST,port),timeout=.1): return
        except OSError: time.sleep(.05)
    raise TimeoutError('SOCKS listener not ready')
def close(p):
    if p is not None:
        if p.poll() is None: p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait()

def connect(proxy,target):
    if proxy is not None: return socks(proxy,1,target)[0]
    s=socket.create_connection((HOST,target),timeout=20); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); return s
def exchange(s,b):
    s.sendall(b)
    if exact(s,len(b))!=b: raise ValueError('TCP exact-byte mismatch')
def udpcheck(proxy,target,count):
    ctl=None; u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(.5)
    try:
        if proxy is None: relay=(HOST,target); prefix=b''
        else:
            ctl,relay=socks(proxy,3,0); prefix=b'\0\0\0\x01'+socket.inet_aton(HOST)+struct.pack('!H',target)
        times=[]; failures=0; cold=None
        for i in range(count+1):
            # XUDP opens its transport lazily on the first datagram. Allow
            # the cold HMC handshake to finish before measuring warm UDP.
            u.settimeout(20 if i == 0 else .5)
            b=struct.pack('!I',i)+b'U'*1468; t=time.perf_counter(); u.sendto(prefix+b,relay)
            try:
                r,_=u.recvfrom(65535)
                if r!=(prefix+b if proxy is not None else b): raise ValueError(f'UDP exact-byte/address mismatch: header={r[:10].hex()} expected={prefix.hex()} payload_equal={r[10:]==b} actual_seq={r[10:14].hex()} expected_seq={b[:4].hex()} length={len(r)}')
                elapsed=(time.perf_counter()-t)*1000
                if i == 0: cold=elapsed
                else: times.append(elapsed)
            except socket.timeout:
                if i == 0: raise TimeoutError('cold UDP transport handshake/echo timed out')
                failures+=1
        return {'sent':count,'received':len(times),'loss':failures,'cold_first_echo_ms':cold,'rtt_ms':times}
    finally:
        u.close()
        if ctl: ctl.close()

def bulk(proxy,target,size,n):
    clock=[]; barrier=threading.Barrier(n+1,action=lambda:clock.append(time.perf_counter()))
    def worker(i):
        # Unique bytes/offsets catch duplicated or reordered chunks; prepare
        # payloads before the barrier, outside the goodput measurement.
        data=memoryview(struct.pack('!Q',i)+secrets.token_bytes(size-8))
        with connect(proxy,target) as s:
            # A SOCKS CONNECT reply does not imply the lazy tunnel handshake
            # finished. Warm each stream before starting the goodput timer.
            exchange(s,struct.pack('!Q',i)+b'B'*56)
            barrier.wait(timeout=30)
            errors=[]
            def receive():
                try:
                    remaining=size
                    while remaining:
                        offset=size-remaining; chunk=data[offset:offset+min(65536,remaining)]
                        if exact(s,len(chunk))!=chunk: raise ValueError('bulk exact-byte mismatch')
                        remaining-=len(chunk)
                except BaseException as e: errors.append(e)
            reader=threading.Thread(target=receive,daemon=True); reader.start()
            try:
                remaining=size
                while remaining:
                    offset=size-remaining; chunk=data[offset:offset+min(65536,remaining)]; s.sendall(chunk); remaining-=len(chunk)
                reader.join(timeout=180)
                if reader.is_alive(): raise TimeoutError('bulk reader')
                if errors: raise errors[0]
            finally:
                if reader.is_alive(): s.shutdown(socket.SHUT_RDWR); reader.join(timeout=5)
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        fs=[pool.submit(worker,i) for i in range(n)]; barrier.wait(timeout=30)
        for f in fs: f.result(timeout=180)
        elapsed=time.perf_counter()-clock[0]
    return {'bytes_per_stream':size,'streams':n,'elapsed_s':elapsed,'application_echo_payload_mib_s':size*n/1048576/elapsed,'definition':'unique application payload echoed, excludes counting return bytes twice'}

def main():
    global ROOT
    ap=argparse.ArgumentParser(); ap.add_argument('--binary',default='/tmp/hitori-hmc-xray'); ap.add_argument('--smoke',action='store_true'); ap.add_argument('--repeats',type=int,default=5); ap.add_argument('--seed',type=int,default=1729); ap.add_argument('--work-dir'); ap.add_argument('--output'); ap.add_argument('--source-root'); ap.add_argument('--modes',nargs='+',choices=MODES,default=MODES[:5]); ap.add_argument('--rtt-ms',type=float,default=0); ap.add_argument('--venc-padding',default=''); ap.add_argument('--no-bulk',action='store_true'); args=ap.parse_args()
    if not args.smoke and args.repeats<5: ap.error('at least five repeats required')
    os.umask(0o077)
    ROOT=Path(args.work_dir or tempfile.mkdtemp(prefix='hitori-hmc-comparison-')).resolve()
    if Path(tempfile.gettempdir()).resolve() not in ROOT.parents: ap.error('work directory must be under the system temp directory')
    if ROOT.exists() and any(ROOT.iterdir()): ap.error('work directory must be empty; each run owns its generated credentials/logs')
    ROOT.mkdir(parents=True,exist_ok=True)
    output=Path(args.output).resolve() if args.output else ROOT/'results.json'
    if ROOT not in output.parents: ap.error('output must be within work directory')
    print(json.dumps({'artifact_dir':str(ROOT),'results_path':str(output)}),flush=True)
    binary=str(Path(args.binary).resolve()); cert=ROOT/'test-cert'; uid=str(uuid.uuid4()); pw=secrets.token_urlsafe(48)
    subprocess.run([binary,'tls','cert','--ca','--domain','localhost','--file',str(cert)],check=True,stdout=subprocess.DEVNULL)
    venc=[l.split('"')[3] for l in subprocess.check_output([binary,'vlessenc'],text=True).splitlines() if l.startswith(('"decryption"','"encryption"'))]
    keys=dict(line.split(': ',1) for line in subprocess.check_output([binary,'x25519'],text=True).splitlines() if ': ' in line)
    def with_padding(v):
        # Optional VLESS Encryption padding spec between the ticket field and the key.
        if not args.venc_padding: return v
        head=v.split('.'); return '.'.join(head[:3]+[args.venc_padding]+head[3:])
    keys['venc_dec'],keys['venc_enc']=with_padding(venc[0]),with_padding(venc[1])  # first pair: X25519 authentication
    tcp,udp,stop=targets(); tp=tcp.getsockname()[1]; up=udp.getsockname()[1]; fb=port(); fallback=None
    report={'binary':binary,'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),'version':subprocess.check_output([binary,'version'],text=True),'platform':platform.platform(),'python':platform.python_version(),'cpu_count':os.cpu_count(),'GOMAXPROCS':os.environ.get('GOMAXPROCS','runtime default'),'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'settings':{'venc_padding':args.venc_padding or 'xray default','rtt_ms':args.rtt_ms,'no_bulk':args.no_bulk,'smoke':args.smoke,'repeats':1 if args.smoke else args.repeats,'seed':args.seed,'bulk_bytes_per_stream':65536 if args.smoke else 32*1024*1024,'warm_count':2 if args.smoke else 40,'udp_count':2 if args.smoke else 40,'quic_congestion':'bbr','tls':'private generated trust anchor, serverName localhost, system roots disabled','reality':'REALITY authenticated public key + hostname, Vision; not ordinary CA-based TLS','scope':'same-host loopback, no network shaping; plaintext application echo does not exercise Vision HTTPS splice optimizations','goodput':'unique echoed payload / elapsed; not wire throughput','cold':'fresh client core to warmed server, process startup excluded; first SOCKS connect plus echo; UDP first echo recorded separately (Hysteria may reuse its QUIC session)','warm':'same established TCP stream; each bulk stream warmed before timed transfer','limits':'Python echo, shared CPU and loopback affect results; HMC experimental; netns/netem future only'},'results':[]}
    if args.source_root:
        source=Path(args.source_root).resolve()
        files=list((source/'transport/internet/finalmask/hmc').glob('*'))
        files += [source/p for p in ('infra/conf/transport_finalmask_hmc.go','infra/conf/transport_internet.go','common/xudp/xudp.go','go.mod','go.sum')]
        report['source_sha256']={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files) if p.is_file()}
    order=[]
    for _ in range(1 if args.smoke else args.repeats):
        names=args.modes[:]; random.Random(args.seed+len(order)).shuffle(names); order.extend(names)
    try:
        f=(ROOT/'fallback.log').open('ab'); fallback=subprocess.Popen(['openssl','s_server','-accept',f'{HOST}:{fb}','-cert',str(cert)+'.crt','-key',str(cert)+'.key','-tls1_3','-alpn','h2','-www'],stdout=f,stderr=subprocess.STDOUT); f.close()
        ready(fallback,fb)
        for index,mode in enumerate(order):
            row={'mode':mode,'order':index,'status':'FAIL'}; server=client=None; delay=None
            try:
                proxy=None
                if mode!='direct':
                    sp,proxy=port(),port(); sc,cc=configs(mode,sp,proxy,cert,uid,pw,keys,fb)
                    if args.rtt_ms:
                        if mode=='hysteria2': raise RuntimeError('delay proxy is TCP-only')
                        dport,delay=delay_proxy(sp,args.rtt_ms/2); cc['outbounds'][0]['settings']['vnext'][0]['port']=dport
                    server=start(binary,sc,ROOT/f'{mode}-server.json',ROOT/f'{mode}-server.log')
                    # Warm server-only initialization using a DISPOSABLE client.
                    # REALITY asynchronously probes its camouflage target at
                    # server startup; do not call that a per-client handshake.
                    probe_cfg=copy.deepcopy(cc); probe_port=port(); probe_cfg['inbounds'][0]['port']=probe_port
                    client=start(binary,probe_cfg,ROOT/f'{mode}-probe.json',ROOT/f'{mode}-probe.log'); ready(client,probe_port)
                    started=time.perf_counter()
                    with connect(probe_port,tp) as probe: exchange(probe,b'P'*64)
                    row['server_warmup_first_echo_ms']=(time.perf_counter()-started)*1000
                    close(client); client=None
                    client=start(binary,cc,ROOT/f'{mode}-client.json',ROOT/f'{mode}-client.log'); ready(client,proxy)
                    if server.poll() is not None: raise RuntimeError('server exited; inspect log')
                before={'server':proc_stats(server),'client':proc_stats(client)}
                t=time.perf_counter()
                with connect(proxy,tp) as c:
                    exchange(c,b'C'*64); row['cold_first_echo_ms']=(time.perf_counter()-t)*1000
                    row['warm_echo_ms']=[]
                    for _ in range(report['settings']['warm_count']):
                        t=time.perf_counter(); exchange(c,b'W'*64); row['warm_echo_ms'].append((time.perf_counter()-t)*1000)
                    t=time.perf_counter()
                    with connect(proxy,tp) as c2: exchange(c2,b'S'*64)
                    row['second_conn_first_echo_ms']=(time.perf_counter()-t)*1000
                row['udp']=udpcheck(proxy,up,report['settings']['udp_count'])
                if row['udp']['loss']: raise RuntimeError('UDP echo loss')
                row['bulk']=[] if args.no_bulk else [bulk(proxy,tp,report['settings']['bulk_bytes_per_stream'],n) for n in (1,8)]
                after={'server':proc_stats(server),'client':proc_stats(client)}; row['process_before']=before; row['process_after']=after
                row['cpu_seconds_delta']={k:after[k]['cpu_seconds']-before[k]['cpu_seconds'] if before[k] else None for k in before}; row['status']='PASS'
            except Exception as e: row['error']=f'{type(e).__name__}: {e}'
            finally:
                close(client); close(server)
                if delay: delay[0].set(); delay[1].close()
            report['results'].append(row); output.write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(row),flush=True)
    finally:
        close(fallback); stop.set(); tcp.close(); udp.close()
    return 0 if all(r['status']=='PASS' for r in report['results']) else 1
if __name__=='__main__': raise SystemExit(main())
