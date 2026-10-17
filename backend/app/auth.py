import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict
from fastapi import HTTPException, Request

COOKIE='sentinel_session'

def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600_000).hex()

class Auth:
    def __init__(self, store, settings):
        self.store=store; self.settings=settings
        self.failures=defaultdict(list)
        path=settings.data_dir/'local-credentials.json'
        if not store.one('SELECT username FROM users LIMIT 1'):
            password=secrets.token_urlsafe(18); salt=secrets.token_hex(16)
            with store.transaction() as db:
                db.execute('INSERT INTO users VALUES(?,?,?)',('analyst',salt,password_hash(password,salt)))
            path.write_text(json.dumps({'username':'analyst','password':password,'sensor_token':secrets.token_urlsafe(32)},indent=2),encoding='utf-8')
            try: path.chmod(0o600)
            except OSError: pass
        if not path.exists(): raise RuntimeError('Missing local-credentials.json: restore it from your private backup; do not reset the database automatically.')
        self.sensor_token=json.loads(path.read_text(encoding='utf-8'))['sensor_token']

    def login(self, username, password, ip):
        now=time.time(); self.failures[ip]=[t for t in self.failures[ip] if now-t<60]
        if len(self.failures[ip])>=5: raise HTTPException(429,'Too many attempts. Try again in one minute.')
        user=self.store.one('SELECT * FROM users WHERE username=?',(username,))
        digest=password_hash(password,user['salt'] if user else '0'*32)
        if not user or not hmac.compare_digest(digest,user['password_hash']):
            self.failures[ip].append(now)
            raise HTTPException(401,'Invalid username or password')
        self.failures[ip]=[]
        token=secrets.token_urlsafe(40); csrf=secrets.token_urlsafe(24)
        with self.store.transaction() as db:
            db.execute('DELETE FROM auth_sessions WHERE expires_at<?',(now,))
            db.execute('INSERT INTO auth_sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),username,csrf,now+self.settings.session_hours*3600))
            self.store.audit(db,username,'login','workspace')
        return token,csrf

    def require(self, request: Request):
        token=request.cookies.get(COOKIE,'')
        session=self.store.one('SELECT * FROM auth_sessions WHERE token_hash=? AND expires_at>?',(hashlib.sha256(token.encode()).hexdigest(),time.time()))
        if not session: raise HTTPException(401,'Sign in to your local workspace')
        if request.method not in ('GET','HEAD','OPTIONS') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session['csrf']):
            raise HTTPException(403,'Missing or invalid CSRF token')
        return {'username':session['username'],'csrf':session['csrf']}

    def require_device(self, request: Request):
        token=request.headers.get('Authorization','').removeprefix('Bearer ')
        if not hmac.compare_digest(token,self.sensor_token): raise HTTPException(401,'Invalid sensor credential')
        return 'external-sensor'
