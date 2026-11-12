# Run: go build -o /tmp/hitori-hmc-xray ./main && python3 testing/hmc_smoke.py
import copy, json, socket, subprocess, tempfile, threading, time, os, struct

def port():
 s=socket.socket(); s.bind(('127.0.0.1',0)); p=s.getsockname()[1]; s.close(); return p
v,s=port(),port(); uid='00112233-4455-4677-8899-aabbccddeeff'
mask={'network':'raw','finalmask':{'tcp':[{'type':'hmc','settings':{'password':'high-entropy-test-password-not-for-production','hostname':'localhost','profiles':[{'username':'TestUser','uuid':uid}]}}]}}
server={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':v,'protocol':'vless','settings':{'clients':[{'id':uid}],'decryption':'none'},'streamSettings':mask}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','network':'tcp,udp','ip':['127.0.0.1/32']}]}}]}
client={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':s,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':v,'users':[{'id':uid,'encryption':'none'}]}]},'streamSettings':mask}]}
tmp=tempfile.TemporaryDirectory(); procs=[]
try:
 cert = tmp.name + '/server'
 subprocess.run(['/tmp/hitori-hmc-xray', 'tls', 'cert', '--ca', '--domain', 'localhost', '--file', cert], check=True, stdout=subprocess.DEVNULL)
 server['inbounds'][0]['streamSettings'] = copy.deepcopy(mask)
 del server['inbounds'][0]['streamSettings']['finalmask']['tcp'][0]['settings']['profiles']
 client['outbounds'][0]['streamSettings'] = copy.deepcopy(mask)
 if os.environ.get('HMC_BASELINE') == '1':
  del server['inbounds'][0]['streamSettings']['finalmask']
  del client['outbounds'][0]['streamSettings']['finalmask']
 server['inbounds'][0]['streamSettings'].update({'security':'tls','tlsSettings':{'certificates':[{'certificateFile':cert+'.crt','keyFile':cert+'.key'}]}})
 client['outbounds'][0]['streamSettings'].update({'security':'tls','tlsSettings':{'serverName':'localhost','disableSystemRoot':True,'certificates':[{'certificateFile':cert+'.crt','usage':'verify'}]}})
 for i,c in enumerate((server,client)):
  name=tmp.name+'/'+str(i)+'.json'; open(name,'w').write(json.dumps(c)); procs.append(subprocess.Popen(['/tmp/hitori-hmc-xray','run','-config',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT))
 time.sleep(2)
 for p in procs:
  if p.poll() is not None: raise Exception(p.stdout.read().decode())
 if os.environ.get('HMC_BASELINE') != '1':
  def varint(n):
   out = bytearray()
   while n > 127: out.append((n & 127) | 128); n >>= 7
   out.append(n); return bytes(out)
  def recv_varint(sock):
   n = shift = 0
   for _ in range(5):
    b = sock.recv(1) if hasattr(sock, 'recv') else sock.read(1)
    if not b: raise EOFError('Minecraft status EOF')
    n |= (b[0] & 127) << shift
    if b[0] < 128: return n
    shift += 7
   raise ValueError('invalid VarInt')
  def read_exact(sock, n):
   out = b''
   while len(out) < n:
    chunk = sock.recv(n-len(out))
    if not chunk: raise EOFError('Minecraft status EOF')
    out += chunk
   return out
  mc = socket.create_connection(('127.0.0.1',v), timeout=10)
  host = b'localhost'; hello = b'\0'+varint(765)+varint(len(host))+host+struct.pack('!H',v)+b'\1'
  mc.sendall(varint(len(hello))+hello+b'\1\0')
  response = read_exact(mc, recv_varint(mc)); assert response[0] == 0
  from io import BytesIO
  data = BytesIO(response[1:]); length = recv_varint(data); status = json.loads(data.read(length)); assert 'version' in status
  mc.sendall(b'\x09\x01'+struct.pack('!q',42)); assert read_exact(mc,recv_varint(mc)) == b'\x01'+struct.pack('!q',42)
  mc.close(); print('Minecraft Java status and ping PASS')
 def target(kind):
  x=socket.socket(socket.AF_INET,kind); x.bind(('127.0.0.1',0)); return x
 tcp=target(socket.SOCK_STREAM); tcp.listen(); udp=target(socket.SOCK_DGRAM)
 def tcpecho():
  def handle(conn):
   with conn:
    while data:=conn.recv(65536): conn.sendall(data)
  while True:
   conn,_=tcp.accept()
   threading.Thread(target=handle,args=(conn,),daemon=True).start()
 def udpecho():
  while True:
   data,addr=udp.recvfrom(65535); udp.sendto(data,addr)
 threading.Thread(target=tcpecho,daemon=True).start(); threading.Thread(target=udpecho,daemon=True).start()
 def socks(cmd,port):
  x=socket.create_connection(('127.0.0.1',s),timeout=25); x.sendall(b'\x05\x01\x00'); assert x.recv(2)==b'\x05\x00'; x.sendall(b'\x05'+bytes([cmd])+b'\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',port)); h=x.recv(10); assert len(h)==10 and h[:2]==b'\x05\x00',h; return x,(socket.inet_ntoa(h[4:8]),struct.unpack('!H',h[8:10])[0])
 c,_=socks(1,tcp.getsockname()[1]); payload=os.urandom(256*1024); c.sendall(payload); recv=b''
 while len(recv)<len(payload):
  try: part=c.recv(65536)
  except Exception:
   print('TCP bytes received before timeout:',len(recv)); raise
  if not part: raise Exception('TCP early EOF')
  recv+=part
 assert recv==payload; print('TCP over verified TLS echo 256 KiB PASS')
 large = os.urandom(4 * 1024 * 1024); chunks = []; errors = []
 def receive_large():
  remaining = len(large)
  try:
   while remaining:
    part = c.recv(min(65536, remaining))
    if not part: raise EOFError('bulk TCP early EOF')
    chunks.append(part); remaining -= len(part)
  except Exception as exc: errors.append(exc)
 started = time.monotonic(); reader = threading.Thread(target=receive_large); reader.start()
 c.sendall(large); reader.join(timeout=30)
 if reader.is_alive(): c.close(); reader.join(); raise TimeoutError('bulk TCP receive')
 if errors: raise errors[0]
 assert b''.join(chunks) == large
 elapsed = time.monotonic() - started
 print(f'TCP TLS echo 4 MiB PASS: {4 / elapsed:.1f} MiB/s application payload (round trip; baseline={os.environ.get("HMC_BASELINE") == "1"})')
 c.close()
 errors = []
 def concurrent_client(index):
  try:
   conn,_ = socks(1,tcp.getsockname()[1]); data = os.urandom(8192); conn.sendall(data)
   result = b''
   while len(result) < len(data):
    chunk = conn.recv(len(data)-len(result))
    if not chunk: raise EOFError('concurrent TCP early EOF')
    result += chunk
   if result != data: raise ValueError('concurrent TCP mismatch')
   conn.close()
  except Exception as exc: errors.append((index, exc))
 workers = [threading.Thread(target=concurrent_client,args=(i,)) for i in range(8)]
 for worker in workers: worker.start()
 for worker in workers: worker.join(timeout=30)
 assert not any(worker.is_alive() for worker in workers), 'concurrent TCP timed out'
 assert not errors, errors
 print('8 concurrent TCP sessions PASS')
 control,relay=socks(3,0); d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); d.settimeout(10)
 # VLESS/XUDP currently drops payloads above buf.Size-666 = 7526 bytes
 # (common/xudp/xudp.go); its drop boundary has a separate Go regression test.
 for size in (1, 512, 1200, 1472, 4096, 7526):
  msg=os.urandom(size); d.sendto(b'\0\0\0\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp.getsockname()[1])+msg,relay)
  try: got,_=d.recvfrom(65535)
  except TimeoutError: raise TimeoutError(f'UDP echo timed out: {size} bytes')
  assert got[10:]==msg, f'UDP echo mismatch: {size}'
 print('UDP SOCKS over verified TLS echo (1–7526 bytes) PASS'); control.close(); d.close()
 bad = copy.deepcopy(client); s = port(); bad['inbounds'][0]['port'] = s
 bad['outbounds'][0]['streamSettings']['tlsSettings']['serverName'] = 'wrong.invalid'
 name = tmp.name + '/bad.json'; open(name, 'w').write(json.dumps(bad))
 procs.append(subprocess.Popen(['/tmp/hitori-hmc-xray','run','-config',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT))
 time.sleep(1)
 bad_conn,_ = socks(1,tcp.getsockname()[1]); bad_conn.settimeout(10); bad_conn.sendall(b'must-not-pass')
 try: response = bad_conn.recv(1024)
 except ConnectionResetError: response = b''
 assert response == b'', 'wrong TLS name was accepted'
 bad_conn.close()
 procs[-1].terminate(); procs[-1].wait(timeout=5)
 bad_log = procs[-1].stdout.read().decode()
 assert 'certificate' in bad_log.lower(), 'expected certificate validation error: ' + bad_log
 print('Wrong TLS server name rejected PASS')
finally:
 for p in procs: p.terminate()
 for p in procs:
  try: p.wait(timeout=5)
  except subprocess.TimeoutExpired: p.kill()
  if p.returncode not in (0, -15): print(p.stdout.read().decode())
 tmp.cleanup()
