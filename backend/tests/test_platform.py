import hashlib
import io
import json
import socket
import zipfile
from datetime import datetime,timezone,timedelta
import pytest
from fastapi.testclient import TestClient
from backend.app.api import create_app
from backend.app.config import Settings
from backend.app.schemas import EventInput
from backend.app.lab import scenario_events

@pytest.fixture
def platform(tmp_path):
    settings=Settings(data_dir=tmp_path,decoy_enabled=False,seed_replay=False,train_model=False)
    app=create_app(settings)
    with TestClient(app) as client:
        credentials=json.loads((tmp_path/'local-credentials.json').read_text())
        response=client.post('/api/auth/login',json={'username':credentials['username'],'password':credentials['password']})
        assert response.status_code==200
        client.headers['X-CSRF-Token']=response.json()['csrf']
        yield client,app,credentials

def test_authentication_csrf_and_origin_boundaries(platform):
    client,app,_=platform
    with TestClient(app) as outsider:
        assert outsider.get('/api/events').status_code==401
        assert outsider.post('/api/ingest/batches',json={'events':[]}).status_code in (401,422)
    token=client.headers.pop('X-CSRF-Token')
    assert client.post('/api/lab/runs',json={'scenario':'scan'}).status_code==403
    client.headers['X-CSRF-Token']=token
    assert client.post('/api/lab/runs',json={'scenario':'scan'},headers={'Origin':'https://untrusted.invalid'}).status_code==403
    assert client.get('/api/summary',headers={'Host':'evil.invalid'}).status_code==400
    assert client.get('/api/auth/session').json()['username']=='analyst'
    assert client.post('/api/auth/logout').status_code==200
    assert client.get('/api/auth/session').status_code==401

def test_batch_idempotency_namespaces_and_identity(platform):
    client,app,credentials=platform
    event=scenario_events('control')[0].model_dump(mode='json')
    event['source']='cowrie'; event['sensor_id']='raspberry-pi'
    header={'Authorization':'Bearer '+credentials['sensor_token']}
    first=client.post('/api/ingest/batches',json={'events':[event]},headers=header)
    assert first.status_code==200 and first.json()['accepted']==1
    assert client.post('/api/ingest/batches',json={'events':[event]},headers=header).json()['duplicates']==1
    live=client.get('/api/events?mode=LIVE').json()['items']
    assert len(live)==1 and live[0]['sensor_id']=='external-sensor'
    assert client.get('/api/events?mode=REPLAY').json()['items']==[]
    assert not client.get('/api/system').json()['pi_connected']
    assert app.state.store.verify_chain()['valid']

def test_rules_and_retransmissions(platform):
    client,app,_=platform
    now=datetime.now(timezone.utc)
    app.state.service.ingest(scenario_events('control',now),'REPLAY')
    assert client.get('/api/findings').json()==[]
    probes=scenario_events('scan',now)
    same_port=[p.model_copy(update={'destination_port':22}) for p in probes]
    app.state.service.ingest(same_port,'REPLAY')
    assert client.get('/api/findings').json()==[]
    new=scenario_events('scan',now,prefix='actual-scan')
    app.state.service.ingest(new,'REPLAY')
    findings=client.get('/api/findings').json()
    assert any(f['rule_id']=='SCAN-001' for f in findings)
    app.state.service.ingest(scenario_events('auth',now,prefix='failed-auth'),'REPLAY')
    findings=client.get('/api/findings').json()
    assert any(f['rule_id']=='AUTH-001' and f['severity']=='high' for f in findings)
    assert len([f for f in findings if f['rule_id']=='SCAN-001'])==1

def test_import_redaction_validation_and_pagination(platform):
    client,app,_=platform
    record={'eventid':'cowrie.login.failed','timestamp':datetime.now(timezone.utc).isoformat(),'session':'demo','src_ip':'203.0.113.9','username':'student','password':'never-preserve-this'}
    response=client.post('/api/imports/cowrie',json={'records':[record]})
    assert response.json()['accepted']==1
    assert client.post('/api/imports/cowrie',json={'records':[record]}).json()['duplicates']==1
    stored=app.state.store.one('SELECT raw FROM events')['raw']
    assert 'never-preserve-this' not in stored and '[REDACTED]' in stored
    app.state.service.ingest(scenario_events('http'),'REPLAY')
    page=client.get('/api/events?limit=3&protocol=HTTP').json()
    assert len(page['items'])==3 and page['next_cursor']
    older=client.get('/api/events',params={'limit':3,'protocol':'HTTP','before':page['next_cursor']}).json()
    assert {x['event_id'] for x in page['items']}.isdisjoint({x['event_id'] for x in older['items']})
    assert client.get('/api/events?limit=9999').status_code==422
    assert client.get('/api/events?mode=FAKE').status_code==422
    bad={**record,'src_ip':'not-an-ip'}
    assert client.post('/api/imports/cowrie',json={'records':[bad]}).status_code==422

def test_case_export_and_tamper_detection(platform):
    client,app,_=platform
    app.state.service.ingest(scenario_events('auth'),'REPLAY')
    finding=client.get('/api/findings').json()[0]
    case=client.post('/api/cases',json={'title':'Authentication evidence','mode':'REPLAY','finding_id':finding['id'],'notes':'<script>never execute</script>'})
    assert case.status_code==201
    cid=case.json()['id']
    assert client.post('/api/cases',json={'title':'Wrong namespace','mode':'LIVE','finding_id':finding['id']}).status_code==404
    export=client.post('/api/cases/'+cid+'/exports')
    assert export.status_code==202
    eid=export.json()['id']
    response=client.get('/api/exports/'+eid+'/download')
    assert response.status_code==200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert {'manifest.json','SHA256SUMS','events.jsonl','redacted-records.jsonl','report.pdf'}==set(archive.namelist())
        assert archive.read('report.pdf').startswith(b'%PDF')
        assert json.loads(archive.read('manifest.json'))['mode']=='REPLAY'
    assert client.get('/api/exports/'+eid+'/verify').json()['valid']
    row=app.state.store.one('SELECT * FROM exports WHERE id=?',(eid,))
    from pathlib import Path
    path=Path(row['path'])
    with zipfile.ZipFile(path) as z: files={name:z.read(name) for name in z.namelist()}
    files['events.jsonl']+=b'altered'
    with zipfile.ZipFile(path,'w') as z:
        for name,body in files.items(): z.writestr(name,body)
    assert not client.get('/api/exports/'+eid+'/verify').json()['valid']
    assert client.patch('/api/cases/'+cid,json={'notes':'Reviewed','status':'reviewed'}).status_code==200
    assert client.get('/api/audit').json()

def test_storage_restart_and_hash_chain(platform,tmp_path):
    client,app,_=platform
    app.state.service.ingest(scenario_events('shell'),'REPLAY')
    key=client.get('/api/sessions').json()[0]['id']
    detail=client.get('/api/sessions/'+key).json()
    assert len(detail['events'])==7
    assert len(detail['findings'])>=2
    assert app.state.store.verify_chain()['valid']
    from backend.app.database import Database
    reopened=Database(tmp_path/'sentinel.db')
    assert reopened.one('SELECT COUNT(*) n FROM events')['n']==7
    with reopened.transaction() as db: db.execute("UPDATE events SET raw='altered' WHERE seq=1")
    assert not reopened.verify_chain()['valid']

def test_live_software_decoy(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    settings=Settings(data_dir=tmp_path,decoy_port=port,seed_replay=False,train_model=False)
    app=create_app(settings)
    with TestClient(app) as client:
        creds=json.loads((tmp_path/'local-credentials.json').read_text())
        client.headers['X-CSRF-Token']=client.post('/api/auth/login',json={'username':'analyst','password':creds['password']}).json()['csrf']
        result=client.post('/api/lab/probe')
        assert result.status_code==200,result.text
        assert result.json()['requests']==20 and result.json()['mode']=='LIVE'
        assert client.get('/api/summary?mode=LIVE').json()['total_events']==20
        assert client.get('/api/summary?mode=REPLAY').json()['total_events']==0
        rules={r['rule_id'] for r in client.get('/api/findings?mode=LIVE').json()}
        assert {'HTTP-001','AUTH-001'}<=rules
        assert all('synthetic-only' not in r['raw'] for r in app.state.store.query('SELECT raw FROM events'))
    assert not app.state.decoy.thread.is_alive()

def test_synthetic_model_provenance_and_reproducibility(tmp_path):
    from backend.app.ml import Intelligence
    from backend.app.detection import features
    model=Intelligence(tmp_path)
    report=model.train()
    assert report['samples']==400 and report['train_runs']==300 and report['test_runs']==100
    assert 'Synthetic' in report['scope']
    assert 0<=report['macro_f1']<=1
    first=report['macro_f1']; dataset=report['dataset_sha256']
    assert model.train()['macro_f1']==first
    assert model.report['dataset_sha256']==dataset
    events=[e.model_dump(mode='json') for e in scenario_events('auth')]
    assert model.predict(features(events))['label']=='auth_guessing'

def test_conflicting_event_id_rolls_back_batch(platform):
    client,app,credentials=platform
    event=scenario_events('control')[0].model_dump(mode='json')
    event['source']='cowrie'
    headers={'Authorization':'Bearer '+credentials['sensor_token']}
    assert client.post('/api/ingest/batches',json={'events':[event]},headers=headers).json()['accepted']==1
    conflict={**event,'detail':'different payload'}
    new={**event,'event_id':'new-before-conflict'}
    response=client.post('/api/ingest/batches',json={'events':[new,conflict]},headers=headers)
    assert response.status_code==409
    assert app.state.store.one('SELECT COUNT(*) n FROM events')['n']==1

def test_health_during_concurrent_wal_retirement(platform):
    client,app,_=platform
    from concurrent.futures import ThreadPoolExecutor
    def visit(index):
        if index%3==0: app.state.service.ingest(scenario_events('control',prefix='concurrent-'+str(index)),'REPLAY')
        return client.get('/api/system').status_code
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert set(pool.map(visit,range(40)))=={200}
    assert app.state.store.verify_chain()['valid']

def test_explicit_fixture_does_not_touch_live(platform):
    client,app,_=platform
    response=client.post('/api/lab/replay-fixture')
    assert response.status_code==200
    assert response.json()['generated']==192
    assert client.get('/api/summary?mode=REPLAY').json()['total_events']==192
    assert client.get('/api/summary?mode=LIVE').json()['total_events']==0

def test_api_body_limit_and_clock_validation(platform):
    client,app,credentials=platform
    assert client.post('/api/auth/login',content=b'x'*(512*1024+1),headers={'Content-Type':'application/json'}).status_code==413
    future=scenario_events('control',datetime.now(timezone.utc)+timedelta(minutes=6))[0].model_dump(mode='json')
    future['source']='cowrie'
    assert client.post('/api/ingest/batches',json={'events':[future]},headers={'Authorization':'Bearer '+credentials['sensor_token']}).status_code==422
    assert app.state.store.one('SELECT COUNT(*) n FROM events')['n']==0
