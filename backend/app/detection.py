from datetime import datetime, timedelta
import json
import uuid

RULE_VERSION='1.0.0'
FEATURE_NAMES=['event_count','distinct_ports','login_failures','command_count','http_requests','distinct_paths','duration_seconds']

def features(events):
    times=[datetime.fromisoformat(e['timestamp']) for e in events]
    return [len(events),len({e['destination_port'] for e in events}),sum(e['kind']=='auth_failure' for e in events),sum(e['kind']=='command' for e in events),sum(e['kind']=='http_request' for e in events),len({e.get('metadata',{}).get('path','') for e in events if e['kind']=='http_request'}),max(0,(max(times)-min(times)).total_seconds()) if times else 0]

class Detector:
    def __init__(self,store): self.store=store

    def evaluate(self,db,event,mode):
        now=datetime.fromisoformat(event['timestamp'])
        # Timestamp windows are event-time windows and cannot consume future records.
        rows=db.execute('SELECT event_id,kind,destination_port,detail,timestamp,metadata FROM events WHERE mode=? AND sensor_id=? AND source_ip=? AND timestamp>=? AND timestamp<=? ORDER BY seq',
            (mode,event['sensor_id'],event['source_ip'],(now-timedelta(seconds=60)).isoformat(timespec='milliseconds'),event['timestamp'])).fetchall()
        rules=[]
        probes=[r for r in rows if r['kind']=='tcp_probe' and datetime.fromisoformat(r['timestamp'])>=now-timedelta(seconds=10)]
        ports=len({r['destination_port'] for r in probes})
        if ports>=10: rules.append(('scan','TCP port scan','medium',f'{ports} distinct TCP destination ports in 10 seconds; threshold 10.','SCAN-001',[r['event_id'] for r in probes]))
        failures=[r for r in rows if r['kind']=='auth_failure']
        if len(failures)>=5: rules.append(('auth_guessing','Repeated authentication failures','high',f'{len(failures)} failed logins in 60 seconds; threshold 5.','AUTH-001',[r['event_id'] for r in failures]))
        http=[r for r in rows if r['kind']=='http_request']
        paths={json.loads(r['metadata']).get('path','/') for r in http}
        if len(http)>=10 and len(paths)>=3: rules.append(('http_probe','HTTP path enumeration','medium',f'{len(http)} HTTP requests across {len(paths)} paths in 60 seconds; thresholds 10 requests / 3 paths.','HTTP-001',[r['event_id'] for r in http]))
        if event['kind']=='command':
            command=event['detail'].lower()
            download=any(x in command for x in ('wget ','curl ','/etc/cron','crontab','chmod +x'))
            rules.append(('shell_activity','Download or persistence intent' if download else 'Emulated shell interaction','high' if download else 'low','Recorded command intent; no command is executed on the host.','CMD-002' if download else 'CMD-001',[event['event_id']]))
        for category,title,severity,reason,rule_id,ids in rules:
            # Fixed source-time minute buckets provide deterministic replay and bounded grouping.
            bucket=int(now.timestamp())//60
            key=f"{mode}:{event['sensor_id']}:{event['source_ip']}:{rule_id}:{bucket}"
            existing=db.execute('SELECT id,event_ids FROM findings WHERE dedup_key=?',(key,)).fetchone()
            if existing:
                merged=list(dict.fromkeys(json.loads(existing['event_ids'])+ids))[-500:]
                db.execute('UPDATE findings SET last_seen=?,occurrences=occurrences+1,reason=?,event_ids=? WHERE id=?',(event['timestamp'],reason,json.dumps(merged),existing['id']))
                fid=existing['id']
            else:
                fid='F-'+uuid.uuid4().hex[:10].upper()
                db.execute('INSERT INTO findings(id,dedup_key,mode,sensor_id,session_id,source_ip,category,title,severity,reason,rule_id,rule_version,first_seen,last_seen,event_ids) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (fid,key,mode,event['sensor_id'],event['session_id'],event['source_ip'],category,title,severity,reason,rule_id,RULE_VERSION,event['timestamp'],event['timestamp'],json.dumps(ids)))
            self.store.change(db,'finding',fid)
