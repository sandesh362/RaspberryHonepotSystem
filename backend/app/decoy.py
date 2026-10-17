import threading
import time
import uuid
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
from .schemas import EventInput,utcnow

PAGE=b'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Gateway administration</title><style>body{background:#eef2f5;color:#243443;font:16px system-ui;max-width:380px;margin:15vh auto;padding:25px}form{display:grid;gap:12px;background:white;padding:28px;border:1px solid #cad5df}input,button{font:inherit;padding:10px}label{display:grid;gap:6px}button{background:#243443;color:white;border:0}small{display:block;margin-top:15px}</style><h1>Gateway administration</h1><form action="/login" method="post"><label>Username<input name="username" autocomplete="off"></label><label>Password<input name="password" type="password" autocomplete="off"></label><button>Sign in</button></form><small>Restricted access</small></html>'''

class LocalDecoy:
    def __init__(self,service,store,port): self.service=service; self.store=store; self.port=port; self.server=None; self.error=None; self.thread=None

    def start(self):
        owner=self
        class Handler(BaseHTTPRequestHandler):
            server_version='Gateway'; sys_version=''
            def log_message(self,*args): pass
            def handle_request(self):
                if self.headers.get('Transfer-Encoding'): self.send_error(400); return
                try: length=int(self.headers.get('Content-Length','0'))
                except ValueError: self.send_error(400); return
                if not 0<=length<=8192: self.send_error(413); return
                data=self.rfile.read(length).decode('utf-8','replace'); path=urlsplit(self.path).path[:500]
                login=self.command=='POST' and path=='/login'
                status=401 if login else 200 if path in ('/','/admin','/login') else 404
                username=parse_qs(data).get('username',[''])[0][:80] if login else ''
                event=EventInput(event_id='http-'+uuid.uuid4().hex,sensor_id='software-lab',source='http-decoy',timestamp=datetime.now(timezone.utc),kind='auth_failure' if login else 'http_request',protocol='HTTP',source_ip=self.client_address[0],source_port=self.client_address[1],destination_port=owner.port,session_id=f'http-{self.client_address[0].replace(".","_")}-{int(time.time())//60}',detail=f'{self.command} {path}',metadata={'method':self.command,'path':path,'status':status,'username':username,'transport':'actual loopback HTTP request','credentials':'password deliberately not retained'})
                try: owner.service.ingest([event],'LIVE')
                except Exception: self.send_error(503,'Collector unavailable'); return
                body=PAGE if status==200 else b'Authentication failed' if login else b'Not found'
                self.send_response(status); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(body)
            do_GET=handle_request
            do_POST=handle_request
            def setup(self):
                super().setup(); self.connection.settimeout(5)
        try:
            server=ThreadingHTTPServer(('127.0.0.1',self.port),Handler)
            server.daemon_threads=True; self.server=server
            self.thread=threading.Thread(target=server.serve_forever,name='local-http-decoy',daemon=True); self.thread.start()
        except OSError as exc: self.error=str(exc)
        with self.store.transaction() as db:
            db.execute("UPDATE sensors SET status=?,last_seen=?,details=? WHERE id='software-lab'",('online' if self.server else 'error',utcnow(),'{"binding":"127.0.0.1","hardware":false}'))

    def close(self):
        if self.server:
            self.server.shutdown(); self.server.server_close()
            if self.thread: self.thread.join(timeout=3)
