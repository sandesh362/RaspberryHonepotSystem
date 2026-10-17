import asyncio
import hashlib
import json
import shutil
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .auth import Auth, COOKIE
from .config import Settings, ROOT
from .database import Database, decode_event, canonical
from .decoy import LocalDecoy
from .evidence import Evidence
from .lab import Lab, SCENARIOS
from .ml import Intelligence
from .schemas import BatchInput,LoginInput,RunInput,CaseInput,CaseUpdate,FindingUpdate,CowrieImport,EventInput,Mode,utcnow
from .service import EventService, EventConflict

PHASES=[
 {'id':'software','name':'Phase 1','period':'Semester VII / evaluation build','status':'implemented','description':'A working software investigation platform. Completion is demonstrated by features and tests, not a percentage estimate.','items':[
  {'name':'Authenticated workspace and API','state':'complete','detail':'Local accounts, session cookies, CSRF checks and a separate device credential.'},
  {'name':'Durable event pipeline','state':'complete','detail':'SQLite WAL, idempotent batches, normalized/redacted records and a hash chain.'},
  {'name':'Software HTTP honeypot','state':'complete','detail':'Actual loopback HTTP requests and failed synthetic logins, collected live.'},
  {'name':'Rule engine and investigation','state':'complete','detail':'Scan/login/HTTP thresholds, command-intent tags, session timeline and cases.'},
  {'name':'Dashboard and evidence exports','state':'complete','detail':'Resumable updates, filters, health, case notes, ZIP/PDF and verification.'},
  {'name':'ML feasibility experiment','state':'lab only','detail':'Random Forest and Isolation Forest trained on synthetic features; no field accuracy claim.'}]},
 {'id':'hardware','name':'Phase 2','period':'Semester VIII / target January-February','status':'planned','description':'Deploy and validate the same pipeline on the actual Raspberry Pi and collect a real dataset.','items':[
  {'name':'Pi 4 / 5 deployment','state':'planned','detail':'ARM64 compatibility, systemd, Ethernet lab and resource profiling.'},
  {'name':'Cowrie and Suricata integration','state':'planned','detail':'Actual SSH/Telnet capture, interface visibility and closed-port observations.'},
  {'name':'Sensor transport and containment','state':'planned','detail':'Durable edge spool, pinned TLS, token rotation, firewall egress policy and outage recovery.'},
  {'name':'Real capture ML evaluation','state':'planned','detail':'Reviewed run/day-separated dataset, tuned thresholds, hybrid ablation and uncertainty.'},
  {'name':'Field reliability and forensic completeness','state':'planned','detail':'Rotation, clock drift, raw-file transfer, PCAP limits, 24-hour soak and negative containment tests.'}]}]

def create_app(settings=None):
    settings=settings or Settings(); settings.data_dir.mkdir(parents=True,exist_ok=True)
    store=Database(settings.data_dir/'sentinel.db'); auth=Auth(store,settings); intelligence=Intelligence(settings.data_dir)
    service=EventService(store,intelligence); evidence=Evidence(store,settings.data_dir); lab=Lab(service,store,settings)
    decoy=LocalDecoy(service,store,settings.decoy_port); probe_lock=asyncio.Lock(); fixture_lock=asyncio.Lock(); last_probe=[0.]

    @asynccontextmanager
    async def lifespan(app):
        if settings.train_model: await asyncio.to_thread(intelligence.train)
        if settings.seed_replay: await asyncio.to_thread(lab.seed)
        if settings.decoy_enabled: decoy.start()
        try: yield
        finally:
            await lab.close()
            if settings.decoy_enabled: await asyncio.to_thread(decoy.close)

    app=FastAPI(title='SentinelPi Control Plane',version='0.1.0',description='Phase 1 local software honeypot and forensic investigation platform.',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    app.state.store=store; app.state.auth=auth; app.state.service=service; app.state.intelligence=intelligence; app.state.lab=lab; app.state.decoy=decoy
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost','testserver'])
    app.add_middleware(CORSMiddleware,allow_origins=list(settings.origins),allow_credentials=True,allow_methods=['GET','POST','PATCH','OPTIONS'],allow_headers=['Content-Type','X-CSRF-Token','Authorization','Last-Event-ID'])

    @app.middleware('http')
    async def boundaries(request,call_next):
        if request.url.path.startswith('/api/'):
            if request.method not in ('GET','HEAD','OPTIONS'):
                origin=request.headers.get('origin')
                if origin and origin not in settings.origins: return JSONResponse({'detail':'Untrusted request origin'},status_code=403)
                chunks=[]; size=0
                async for chunk in request.stream():
                    size+=len(chunk)
                    if size>512*1024: return JSONResponse({'detail':'Request body exceeds 512 KiB'},status_code=413)
                    chunks.append(chunk)
                request._body=b''.join(chunks)
            response=await call_next(request)
            response.headers['Cache-Control']='no-store'
        else: response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Content-Security-Policy']="default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.exception_handler(EventConflict)
    async def event_conflict(request, exc):
        return JSONResponse({'detail':str(exc)},status_code=409)

    @app.get('/api/health')
    def public_health(): return {'status':'ok','service':'SentinelPi','version':'0.1.0','time':utcnow()}

    @app.post('/api/auth/login')
    def login(body:LoginInput,request:Request):
        token,csrf=auth.login(body.username,body.password,request.client.host)
        response=JSONResponse({'username':body.username,'csrf':csrf})
        response.set_cookie(COOKIE,token,max_age=settings.session_hours*3600,httponly=True,samesite='strict',secure=False,path='/')
        return response

    @app.get('/api/auth/session')
    def session(user=Depends(auth.require)): return user

    @app.post('/api/auth/logout')
    def logout(request:Request,user=Depends(auth.require)):
        with store.transaction() as db:
            db.execute('DELETE FROM auth_sessions WHERE token_hash=?',(hashlib.sha256(request.cookies.get(COOKIE,'').encode()).hexdigest(),))
            store.audit(db,user['username'],'logout','workspace')
        response=JSONResponse({'ok':True}); response.delete_cookie(COOKIE); return response

    @app.get('/api/openapi.json')
    def schema(user=Depends(auth.require)): return app.openapi()

    @app.get('/api/summary')
    def summary(mode:Mode='REPLAY',user=Depends(auth.require)): return service.summary(mode)

    @app.get('/api/events')
    def events(mode:Mode='REPLAY',limit:int=Query(50,ge=1,le=200),before:int|None=Query(None,ge=1),q:str=Query('',max_length=160),protocol:str=Query('',max_length=12),kind:str=Query('',max_length=40),user=Depends(auth.require)):
        return service.events(mode,limit,before,q,protocol,kind)

    @app.get('/api/events/{event_id}')
    def event(event_id:str,user=Depends(auth.require)):
        row=store.one('SELECT * FROM events WHERE event_id=?',(event_id,))
        if not row: raise HTTPException(404,'Event not found')
        return {**decode_event(row),'preserved_record':json.loads(row['raw'])}

    @app.post('/api/ingest/batches')
    def ingest(body:BatchInput,request:Request):
        sensor=auth.require_device(request)
        for event in body.events:
            if event.source not in ('cowrie','suricata'): raise HTTPException(422,'Device source must be cowrie or suricata')
            if event.timestamp>datetime.now(timezone.utc)+timedelta(minutes=5): raise HTTPException(422,'Sensor clock is more than five minutes ahead')
            event.sensor_id=sensor
        result=service.ingest(body.events,'LIVE')
        with store.transaction() as db: db.execute("UPDATE sensors SET status='receiving' WHERE id=?",(sensor,))
        return result

    @app.post('/api/sensors/heartbeat')
    async def heartbeat(request:Request):
        sensor=auth.require_device(request)
        with store.transaction() as db:
            db.execute("UPDATE sensors SET status='online',last_seen=? WHERE id=?",(utcnow(),sensor)); store.change(db,'sensor',sensor)
        return {'accepted':True,'server_time':utcnow()}

    @app.get('/api/sessions')
    def sessions(mode:Mode='REPLAY',user=Depends(auth.require)):
        rows=store.query('SELECT * FROM sessions WHERE mode=? ORDER BY last_seen DESC LIMIT 100',(mode,))
        return [{**r,'prediction':json.loads(r['prediction'])} for r in rows]

    @app.get('/api/sessions/{key}')
    def session_detail(key:str,user=Depends(auth.require)):
        row=store.one('SELECT * FROM sessions WHERE id=?',(key,))
        if not row: raise HTTPException(404,'Session not found')
        events=store.query('SELECT * FROM events WHERE mode=? AND sensor_id=? AND session_id=? ORDER BY seq LIMIT 1000',(row['mode'],row['sensor_id'],row['source_session_id']))
        findings=store.query('SELECT * FROM findings WHERE mode=? AND sensor_id=? AND session_id=? ORDER BY first_seen',(row['mode'],row['sensor_id'],row['source_session_id']))
        return {**row,'prediction':json.loads(row['prediction']),'events':[decode_event(e) for e in events],'findings':findings,'truncated':row['event_count']>1000}

    @app.get('/api/findings')
    def findings(mode:Mode='REPLAY',status:str=Query('',max_length=20),user=Depends(auth.require)):
        sql='SELECT * FROM findings WHERE mode=?'; args=[mode]
        if status: sql+=' AND status=?'; args.append(status)
        return store.query(sql+' ORDER BY CASE severity WHEN \'high\' THEN 0 WHEN \'medium\' THEN 1 ELSE 2 END,last_seen DESC LIMIT 200',args)

    @app.patch('/api/findings/{fid}')
    def update_finding(fid:str,body:FindingUpdate,user=Depends(auth.require)):
        if not store.one('SELECT id FROM findings WHERE id=?',(fid,)): raise HTTPException(404,'Finding not found')
        with store.transaction() as db:
            db.execute('UPDATE findings SET status=? WHERE id=?',(body.status,fid)); store.audit(db,user['username'],'finding-status',fid,body.status); store.change(db,'finding',fid)
        return {'ok':True}

    @app.get('/api/cases')
    def cases(mode:Mode='REPLAY',user=Depends(auth.require)):
        rows=store.query('SELECT * FROM cases WHERE mode=? ORDER BY created_at DESC',(mode,))
        return [{**r,'event_count':len(json.loads(r['event_ids'])),'exports':store.query('SELECT id,status,created_at,sha256,error FROM exports WHERE case_id=? ORDER BY created_at DESC',(r['id'],))} for r in rows]

    @app.post('/api/cases',status_code=201)
    def create_case(body:CaseInput,user=Depends(auth.require)):
        session_key=body.session_id
        if body.finding_id:
            finding=store.one('SELECT * FROM findings WHERE id=? AND mode=?',(body.finding_id,body.mode))
            if not finding: raise HTTPException(404,'Finding not found in this data mode')
            session_key=f"{body.mode}:{finding['sensor_id']}:{finding['session_id']}"
        if not session_key: raise HTTPException(422,'Choose a finding or session for an evidence case')
        row=store.one('SELECT * FROM sessions WHERE id=? AND mode=?',(session_key,body.mode))
        if not row: raise HTTPException(404,'Session not found in this data mode')
        ids=store.query('SELECT event_id FROM events WHERE mode=? AND sensor_id=? AND session_id=? ORDER BY seq LIMIT 2001',(body.mode,row['sensor_id'],row['source_session_id']))
        if len(ids)>2000: raise HTTPException(422,'Case exceeds 2,000 event export limit')
        cid='CASE-'+uuid.uuid4().hex[:8].upper(); now=utcnow()
        with store.transaction() as db:
            db.execute('INSERT INTO cases(id,title,mode,finding_id,session_id,notes,created_at,updated_at,event_ids) VALUES(?,?,?,?,?,?,?,?,?)',(cid,body.title,body.mode,body.finding_id,session_key,body.notes,now,now,json.dumps([r['event_id'] for r in ids])))
            store.audit(db,user['username'],'create-case',cid); store.change(db,'case',cid)
        return {'id':cid,'event_count':len(ids)}

    @app.patch('/api/cases/{cid}')
    def update_case(cid:str,body:CaseUpdate,user=Depends(auth.require)):
        if not store.one('SELECT id FROM cases WHERE id=?',(cid,)): raise HTTPException(404,'Case not found')
        with store.transaction() as db:
            db.execute('UPDATE cases SET notes=?,status=?,updated_at=? WHERE id=?',(body.notes,body.status,utcnow(),cid)); store.audit(db,user['username'],'update-case',cid,body.status); store.change(db,'case',cid)
        return {'ok':True}

    @app.post('/api/cases/{cid}/exports',status_code=202)
    def export_case(cid:str,tasks:BackgroundTasks,user=Depends(auth.require)):
        case=store.one('SELECT * FROM cases WHERE id=?',(cid,))
        if not case: raise HTTPException(404,'Case not found')
        pending=store.one("SELECT COUNT(*) n FROM exports WHERE status='pending'")['n']
        if pending>=2: raise HTTPException(429,'Two exports are already queued')
        eid='EXP-'+uuid.uuid4().hex[:10].upper()
        with store.transaction() as db:
            db.execute("INSERT INTO exports(id,case_id,status,created_at) VALUES(?,?,'pending',?)",(eid,cid,utcnow())); store.audit(db,user['username'],'request-export',eid)
        tasks.add_task(evidence.create_export,eid,case)
        return {'id':eid,'status':'pending'}

    @app.get('/api/exports/{eid}/download')
    def download_export(eid:str,user=Depends(auth.require)):
        row=store.one('SELECT * FROM exports WHERE id=?',(eid,))
        if not row: raise HTTPException(404,'Export not found')
        if row['status']!='ready': raise HTTPException(409,'Export is not ready')
        if not Path(row['path']).exists(): raise HTTPException(410,'Export file is missing')
        return FileResponse(row['path'],media_type='application/zip',filename=eid+'.zip')

    @app.get('/api/exports/{eid}/verify')
    def verify_export(eid:str,user=Depends(auth.require)):
        row=store.one("SELECT * FROM exports WHERE id=? AND status='ready'",(eid,))
        if not row: raise HTTPException(404,'Ready export not found')
        try: return evidence.verify(row)
        except (OSError,ValueError,KeyError,zipfile.BadZipFile) as exc: raise HTTPException(409,'Evidence verification failed: '+str(exc))

    @app.get('/api/integrity')
    def integrity(user=Depends(auth.require)): return store.verify_chain()

    @app.get('/api/sensors')
    def sensors(user=Depends(auth.require)):
        rows=store.query('SELECT * FROM sensors')
        for row in rows:
            row['details']=json.loads(row['details'])
            if row['id']=='software-lab':
                row['status']='online' if decoy.server else 'disabled' if not settings.decoy_enabled else 'error'
                row['last_seen']=utcnow() if decoy.server else row['last_seen']
                row['details'].update(port=settings.decoy_port,error=decoy.error)
            if row['kind']=='external' and row['last_seen']:
                age=(datetime.now(timezone.utc)-datetime.fromisoformat(row['last_seen'])).total_seconds()
                if age>60: row['status']='offline'
                elif age>30: row['status']='stale'
        return rows

    @app.get('/api/system')
    def system(user=Depends(auth.require)):
        disk=shutil.disk_usage(settings.data_dir); dbsize=0
        for path in settings.data_dir.glob('sentinel.db*'):
            try: dbsize+=path.stat().st_size
            except FileNotFoundError: pass  # SQLite can retire WAL/SHM between listing and stat.
        return {'database_bytes':dbsize,'disk_free_bytes':disk.free,'storage':'SQLite WAL; synchronous FULL','binding':'127.0.0.1','version':'0.1.0','phase':'Phase 1 / software','pi_connected':False,'collector_spool':'Phase 2: current software decoy commits directly','model_status':intelligence.report['status'],'decoy_error':decoy.error,'changes_cursor':store.one('SELECT COALESCE(MAX(id),0) id FROM changes')['id'],'time':utcnow()}

    @app.get('/api/models')
    def models(user=Depends(auth.require)): return intelligence.report

    @app.post('/api/models/train')
    async def train(user=Depends(auth.require)):
        result=await asyncio.to_thread(intelligence.train)
        with store.transaction() as db: store.audit(db,user['username'],'train-synthetic-model',result['model_id']); store.change(db,'model',result['model_id'])
        return result

    @app.get('/api/project')
    def project(user=Depends(auth.require)): return {'name':'SentinelPi','title':'Intelligent Raspberry Pi-Based Honeypot for Cyber Attack Detection, Logging and Forensic Analysis','phases':PHASES,'cost':'Local core uses free/open-source dependencies; no hosted service or API payment required.','sources':[{'name':'Cowrie documentation','url':'https://docs.cowrie.org/en/stable/'},{'name':'Suricata documentation','url':'https://docs.suricata.io/en/stable/'},{'name':'scikit-learn','url':'https://scikit-learn.org/stable/'},{'name':'NIST SP 800-86','url':'https://csrc.nist.gov/pubs/sp/800/86/final'}]}

    @app.get('/api/architecture.pdf')
    def architecture(user=Depends(auth.require)): return FileResponse(ROOT/'output/pdf/honeypot-system-architecture.pdf',media_type='application/pdf')

    @app.get('/api/audit')
    def audit(user=Depends(auth.require)): return store.query('SELECT * FROM audit ORDER BY id DESC LIMIT 100')

    @app.get('/api/lab/scenarios')
    def scenarios(user=Depends(auth.require)): return SCENARIOS

    @app.get('/api/lab/runs')
    def runs(user=Depends(auth.require)): return list(reversed(list(lab.runs.values())))[0:25]

    @app.post('/api/lab/runs',status_code=202)
    async def start_run(body:RunInput,user=Depends(auth.require)):
        try: return lab.start(body.scenario)
        except ValueError as exc: raise HTTPException(409,str(exc))

    @app.post('/api/lab/runs/{rid}/stop')
    async def stop_run(rid:str,user=Depends(auth.require)):
        try: return lab.stop(rid)
        except KeyError: raise HTTPException(404,'Run not found')

    @app.post('/api/lab/replay-fixture')
    async def replay_fixture(user=Depends(auth.require)):
        if fixture_lock.locked(): raise HTTPException(409,'A replay fixture is already loading')
        async with fixture_lock:
            await asyncio.to_thread(lab.seed,True)
        return {'mode':'REPLAY','generated':192,'scope':'Generated fixture spread across the preceding hour; not network traffic.'}

    @app.post('/api/lab/probe')
    async def probe(user=Depends(auth.require)):
        if probe_lock.locked() or time.monotonic()-last_probe[0]<5: raise HTTPException(429,'Wait five seconds before another local test')
        async with probe_lock:
            try:
                result=await asyncio.to_thread(lab.live_probe); last_probe[0]=time.monotonic(); return result
            except Exception as exc: raise HTTPException(503,'Local decoy test failed: '+str(exc))

    @app.post('/api/imports/cowrie')
    def import_cowrie(body:CowrieImport,user=Depends(auth.require)):
        mapping={'cowrie.login.failed':'auth_failure','cowrie.login.success':'auth_success','cowrie.command.input':'command','cowrie.session.connect':'connection','cowrie.session.closed':'connection'}
        events=[]; originals=[]
        for raw in body.records:
            if raw.get('eventid') not in mapping: continue
            sid=str(raw.get('session','unknown'))
            sid='cowrie-'+hashlib.sha256(sid.encode()).hexdigest()[:24]
            try:
                event=EventInput(event_id='import-'+hashlib.sha256(canonical(raw).encode()).hexdigest()[:32],sensor_id='replay-lab',source='cowrie',timestamp=raw['timestamp'],kind=mapping[raw['eventid']],protocol='TELNET' if raw.get('protocol')=='telnet' else 'SSH',source_ip=raw['src_ip'],destination_port=int(raw.get('dst_port',2222)),session_id=sid,detail=str(raw.get('input',raw['eventid']))[:4096],metadata={'username':raw.get('username',''),'imported':True})
            except (ValueError,KeyError,TypeError) as exc: raise HTTPException(422,'Invalid Cowrie record: '+str(exc))
            events.append(event); originals.append(raw)
        if not events: raise HTTPException(422,'No supported Cowrie events were found')
        result=service.ingest(events,'REPLAY',originals)
        with store.transaction() as db: store.audit(db,user['username'],'import-cowrie','replay-lab',str(len(events))+' supported records')
        return result

    @app.get('/api/stream')
    async def stream(request:Request,after:int=Query(0,ge=0),user=Depends(auth.require)):
        try: cursor=max(after,int(request.headers.get('last-event-id','0')))
        except ValueError: raise HTTPException(422,'Invalid change cursor')
        async def generate():
            nonlocal cursor
            while not await request.is_disconnected():
                # Session expiry is enforced even on long-lived connections.
                try: auth.require(request)
                except HTTPException: return
                rows=await asyncio.to_thread(store.query,'SELECT * FROM changes WHERE id>? ORDER BY id LIMIT 100',(cursor,))
                if rows:
                    for row in rows:
                        cursor=row['id']
                        yield f"id: {cursor}\nevent: change\ndata: {canonical(row)}\n\n"
                else: yield ': heartbeat\n\n'
                await asyncio.sleep(1)
        return StreamingResponse(generate(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

    @app.get('/api/{unknown:path}')
    def unknown_api(unknown:str): raise HTTPException(404,'API endpoint not found')

    if settings.frontend_dir.exists():
        app.mount('/',StaticFiles(directory=settings.frontend_dir,html=True),name='frontend')
    else:
        @app.get('/')
        def missing_frontend(): return JSONResponse({'message':'Frontend not built. Run npm ci and npm run build in frontend/, then restart.'},status_code=503)
    return app
