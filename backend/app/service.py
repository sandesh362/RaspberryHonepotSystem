import hashlib
import json
from datetime import datetime, timezone
from .database import canonical, decode_event
from .detection import Detector, features
from .schemas import utcnow

SECRET_KEYS={'password','passwd','secret','authorization','cookie','token','api_key'}

def redact(value):
    if isinstance(value,dict): return {k:('[REDACTED]' if k.lower() in SECRET_KEYS else redact(v)) for k,v in value.items()}
    if isinstance(value,list): return [redact(v) for v in value]
    return value

class EventConflict(ValueError): pass

class EventService:
    def __init__(self,store,intelligence):
        self.store=store; self.intelligence=intelligence; self.detector=Detector(store)
        with store.transaction() as db:
            db.execute("INSERT OR IGNORE INTO sensors VALUES('software-lab','Local HTTP decoy','software','starting',NULL,'{}')")
            db.execute("INSERT OR IGNORE INTO sensors VALUES('replay-lab','Guided lab replay','replay','available',NULL,'{}')")
            db.execute("INSERT OR IGNORE INTO sensors VALUES('external-sensor','External collector','external','not connected',NULL,'{}')")
            db.execute("INSERT OR IGNORE INTO sensors VALUES('raspberry-pi','Raspberry Pi 4 / 5','hardware','phase 2',NULL,'{}')")

    def ingest(self,inputs,mode,raw_records=None):
        outcomes=[]
        with self.store.transaction() as db:
            for i,item in enumerate(inputs):
                event=item.model_dump(mode='json')
                event['timestamp']=item.timestamp.astimezone(timezone.utc).isoformat(timespec='milliseconds')
                event['metadata']=redact(event['metadata']); event['mode']=mode
                existing=db.execute('SELECT raw FROM events WHERE event_id=?',(event['event_id'],)).fetchone()
                if existing:
                    if canonical(json.loads(existing['raw'])['event'])!=canonical(event):
                        raise EventConflict('Event ID already exists with a different payload or namespace: '+event['event_id'])
                    outcomes.append({'event_id':event['event_id'],'status':'duplicate'}); continue
                if not db.execute('SELECT 1 FROM sensors WHERE id=?',(event['sensor_id'],)).fetchone(): raise ValueError('Unknown sensor identity')
                raw=canonical({'event':event,'source_record':redact(raw_records[i]) if raw_records else None,'redaction':'Credential fields removed at collection; this is the preserved redacted record.'})
                previous=db.execute('SELECT record_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
                previous=previous[0] if previous else '0'*64
                record_hash=hashlib.sha256((previous+raw).encode()).hexdigest(); received=utcnow()
                values=(event['event_id'],mode,event['sensor_id'],event['source'],event['timestamp'],received,event['kind'],event['protocol'],event['source_ip'],event['source_port'],event['destination_port'],event['session_id'],event['detail'],canonical(event['metadata']),raw,previous,record_hash)
                db.execute('INSERT INTO events(event_id,mode,sensor_id,source,timestamp,received_at,kind,protocol,source_ip,source_port,destination_port,session_id,detail,metadata,raw,prev_hash,record_hash) VALUES('+','.join(['?']*17)+')',values)
                key=f"{mode}:{event['sensor_id']}:{event['session_id']}"
                db.execute('INSERT INTO sessions(id,source_session_id,mode,sensor_id,source_ip,protocol,first_seen,last_seen,event_count) VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),first_seen=MIN(first_seen,excluded.first_seen),event_count=event_count+1',
                    (key,event['session_id'],mode,event['sensor_id'],event['source_ip'],event['protocol'],event['timestamp'],event['timestamp']))
                session_events=[decode_event(r) for r in db.execute('SELECT * FROM events WHERE mode=? AND sensor_id=? AND session_id=? ORDER BY seq LIMIT 1000',(mode,event['sensor_id'],event['session_id']))]
                db.execute('UPDATE sessions SET prediction=? WHERE id=?',(canonical(self.intelligence.predict(features(session_events))),key))
                self.detector.evaluate(db,event,mode)
                db.execute('UPDATE sensors SET last_seen=? WHERE id=?',(received,event['sensor_id']))
                self.store.change(db,'event',event['event_id'])
                outcomes.append({'event_id':event['event_id'],'status':'accepted'})
        return {'outcomes':outcomes,'accepted':sum(x['status']=='accepted' for x in outcomes),'duplicates':sum(x['status']=='duplicate' for x in outcomes),'cursor':self.store.one('SELECT COALESCE(MAX(id),0) AS id FROM changes')['id']}

    def events(self,mode,limit=50,before=None,q='',protocol='',kind=''):
        clauses=['mode=?']; args=[mode]
        if before: clauses.append('seq<?'); args.append(before)
        if q: clauses.append('(source_ip LIKE ? OR detail LIKE ? OR event_id LIKE ?)'); args += ['%'+q+'%']*3
        if protocol: clauses.append('protocol=?'); args.append(protocol)
        if kind: clauses.append('kind=?'); args.append(kind)
        rows=self.store.query('SELECT * FROM events WHERE '+' AND '.join(clauses)+' ORDER BY seq DESC LIMIT ?',args+[limit+1])
        more=len(rows)>limit; rows=rows[:limit]
        return {'items':[decode_event(r) for r in rows],'next_cursor':rows[-1]['seq'] if more else None}

    def summary(self,mode):
        total=self.store.one('SELECT COUNT(*) n,COUNT(DISTINCT source_ip) sources,MAX(received_at) latest FROM events WHERE mode=?',(mode,))
        sessions=self.store.one('SELECT COUNT(*) n FROM sessions WHERE mode=?',(mode,))['n']
        findings=self.store.query('SELECT severity,COUNT(*) n FROM findings WHERE mode=? AND status=? GROUP BY severity',(mode,'open'))
        protocols=self.store.query('SELECT protocol,COUNT(*) count FROM events WHERE mode=? GROUP BY protocol ORDER BY count DESC',(mode,))
        categories=self.store.query('SELECT category,COUNT(*) count FROM findings WHERE mode=? GROUP BY category ORDER BY count DESC',(mode,))
        sources=self.store.query('SELECT source_ip,COUNT(*) count,MAX(timestamp) last_seen FROM events WHERE mode=? GROUP BY source_ip ORDER BY count DESC LIMIT 5',(mode,))
        now=datetime.now(timezone.utc); buckets=[]
        for back in reversed(range(12)):
            start=int(now.timestamp()//300)*300-back*300; end=start+300
            a=datetime.fromtimestamp(start,timezone.utc).isoformat(timespec='milliseconds'); b=datetime.fromtimestamp(end,timezone.utc).isoformat(timespec='milliseconds')
            count=self.store.one('SELECT COUNT(*) n FROM events WHERE mode=? AND timestamp>=? AND timestamp<?',(mode,a,b))['n']
            alerts=self.store.one('SELECT COUNT(*) n FROM findings WHERE mode=? AND first_seen>=? AND first_seen<?',(mode,a,b))['n']
            buckets.append({'time':a,'events':count,'findings':alerts})
        return {'mode':mode,'total_events':total['n'],'unique_sources':total['sources'],'session_count':sessions,'last_ingested':total['latest'],'open_findings':sum(r['n'] for r in findings),'high_findings':sum(r['n'] for r in findings if r['severity']=='high'),'severities':findings,'protocols':protocols,'categories':categories,'top_sources':sources,'activity':buckets,'chart_scope':'Last 60 minutes, five-minute buckets, source event time','rule_version':'1.0.0','generated_at':utcnow()}
