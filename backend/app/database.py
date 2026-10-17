import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from .schemas import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO meta VALUES('schema_version','1');
CREATE TABLE IF NOT EXISTS sensors(id TEXT PRIMARY KEY, name TEXT, kind TEXT, status TEXT, last_seen TEXT, details TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, mode TEXT NOT NULL, sensor_id TEXT NOT NULL REFERENCES sensors(id), source TEXT NOT NULL, timestamp TEXT NOT NULL, received_at TEXT NOT NULL, kind TEXT NOT NULL, protocol TEXT NOT NULL, source_ip TEXT NOT NULL, source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL, session_id TEXT NOT NULL, detail TEXT NOT NULL, metadata TEXT NOT NULL, raw TEXT NOT NULL, prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS event_mode_seq ON events(mode, seq DESC);
CREATE INDEX IF NOT EXISTS event_window ON events(mode,sensor_id,source_ip,timestamp);
CREATE INDEX IF NOT EXISTS event_session ON events(mode,sensor_id,session_id,seq);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, source_session_id TEXT NOT NULL, mode TEXT NOT NULL, sensor_id TEXT NOT NULL, source_ip TEXT NOT NULL, protocol TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL, prediction TEXT NOT NULL DEFAULT '{}', UNIQUE(mode,sensor_id,source_session_id));
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, mode TEXT NOT NULL, sensor_id TEXT NOT NULL, session_id TEXT NOT NULL, source_ip TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, reason TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1, event_ids TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS finding_mode_time ON findings(mode,last_seen DESC);
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title TEXT NOT NULL, mode TEXT NOT NULL, finding_id TEXT, session_id TEXT, notes TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, event_ids TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exports(id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), status TEXT NOT NULL, created_at TEXT NOT NULL, path TEXT, sha256 TEXT, error TEXT, manifest TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, timestamp TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, target TEXT NOT NULL, timestamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,salt TEXT NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires_at REAL NOT NULL);
"""

class Database:
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript(SCHEMA)
            version=db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            if version != '1': raise RuntimeError('Unsupported database schema')
            db.execute("UPDATE exports SET status='failed',error='Server restarted before export completed' WHERE status='pending'")
            db.commit()

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('PRAGMA busy_timeout=15000')
        return conn

    @contextmanager
    def transaction(self):
        with self.lock:
            db = self.connect()
            try:
                db.execute('BEGIN IMMEDIATE')
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally: db.close()

    def query(self, sql, args=()):
        db=self.connect()
        try: return [dict(r) for r in db.execute(sql,args).fetchall()]
        finally: db.close()

    def one(self, sql, args=()):
        rows=self.query(sql,args)
        return rows[0] if rows else None

    def change(self, db, kind, target):
        db.execute('INSERT INTO changes(kind,target,timestamp) VALUES(?,?,?)',(kind,target,utcnow()))

    def audit(self, db, actor, action, target, detail=''):
        db.execute('INSERT INTO audit(actor,action,target,timestamp,detail) VALUES(?,?,?,?,?)',(actor,action,target,utcnow(),detail))

    def verify_chain(self):
        previous='0'*64
        checked=0
        for row in self.query('SELECT seq,raw,prev_hash,record_hash FROM events ORDER BY seq'):
            expected=hashlib.sha256((previous+row['raw']).encode()).hexdigest()
            if row['prev_hash']!=previous or row['record_hash']!=expected:
                return {'valid':False,'checked':checked,'failed_sequence':row['seq']}
            previous=row['record_hash']; checked+=1
        return {'valid':True,'checked':checked,'root_hash':previous,'scope':'Local database chain; retain an independent anchor for stronger assurance.'}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)

def decode_event(row):
    row=dict(row)
    row['metadata']=json.loads(row['metadata'])
    row.pop('raw',None)
    return row
