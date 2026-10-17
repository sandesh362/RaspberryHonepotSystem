import hashlib
import io
import json
from pathlib import Path
import zipfile
from html import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,KeepTogether
from reportlab.lib.pagesizes import A4
from .database import canonical
from .schemas import utcnow

def pdf_report(case,events,anchor):
    result=io.BytesIO(); styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Record',fontName='Helvetica',fontSize=8,leading=11,spaceAfter=6))
    def safe(text): return escape(str(text).encode('ascii','backslashreplace').decode())
    elements=[Paragraph('SentinelPi / Investigation report',styles['Title']),Paragraph(safe(case['title']),styles['Heading2']),Paragraph(f"Case {safe(case['id'])} | {safe(case['mode'])} | Generated {safe(utcnow())}",styles['Record']),Spacer(1,10),Paragraph('Scope and provenance',styles['Heading2']),Paragraph('REPLAY records are synthetic or imported lab data. LIVE records originate from the local software decoy or an authenticated external collector. Raspberry Pi deployment is not part of Phase 1. No attacker identity or exploit success is established.',styles['BodyText']),Spacer(1,10),Paragraph('Preservation',styles['Heading2']),Paragraph('Credential fields were removed at collection. The package contains preserved redacted records and ingestion chain links. Checksums establish byte integrity against this package, not independent authenticity. Retain the package hash outside the collector.',styles['BodyText']),Spacer(1,8),Paragraph('Case notes',styles['Heading2']),Paragraph(safe(case['notes'] or 'No notes recorded.'),styles['BodyText']),Spacer(1,8),Paragraph(f'Selected records: {len(events)}',styles['Heading2']),Paragraph('Export chain anchor: '+safe(anchor),styles['Record']),Spacer(1,12)]
    for event in events[:150]:
        record=json.loads(event['raw'])['event']
        elements.append(KeepTogether([Paragraph(safe(f"#{event['seq']} {record['timestamp']} | {record['protocol']} | {record['source_ip']} | {record['kind']}"),styles['Record']),Paragraph(safe(record['detail']),styles['Record'])]))
    if len(events)>150: elements.append(Paragraph('PDF lists the first 150 records. The complete selected dataset is in events.jsonl.',styles['BodyText']))
    def footer(c,doc):
        c.setStrokeColor(colors.HexColor('#d0dadd')); c.line(40,36,A4[0]-40,36); c.setFont('Helvetica',8); c.drawString(40,24,'SentinelPi | Phase 1 software investigation | '+case['mode']); c.drawRightString(A4[0]-40,24,str(doc.page))
    SimpleDocTemplate(result,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=42,bottomMargin=50,title=case['title'],author='SentinelPi').build(elements,onFirstPage=footer,onLaterPages=footer)
    return result.getvalue()

class Evidence:
    def __init__(self,store,data_dir): self.store=store; self.directory=data_dir/'exports'; self.directory.mkdir(exist_ok=True)

    def create_export(self,export_id,case):
        path=self.directory/(export_id+'.zip')
        try:
            ids=json.loads(case['event_ids'])
            if not ids: raise ValueError('Case has no selected events')
            events=self.store.query('SELECT * FROM events WHERE event_id IN ('+','.join('?'*len(ids))+') ORDER BY seq',ids)
            anchor=events[-1]['record_hash']
            raw=('\n'.join(canonical({'seq':e['seq'],'prev_hash':e['prev_hash'],'record_hash':e['record_hash'],'record':json.loads(e['raw'])}) for e in events)+'\n').encode()
            normalized=('\n'.join(canonical(json.loads(e['raw'])['event']) for e in events)+'\n').encode()
            files={'events.jsonl':normalized,'redacted-records.jsonl':raw,'report.pdf':pdf_report(case,events,anchor)}
            manifest={'version':'1','export_id':export_id,'case_id':case['id'],'mode':case['mode'],'created_at':utcnow(),'event_count':len(events),'missing_event_ids':sorted(set(ids)-{e['event_id'] for e in events}),'redaction':'Credential fields removed at collection. Raw source files/PCAP are not captured by Phase 1.','rule_version':'1.0.0','model_scope':'rf-lab-v1; synthetic benchmark, provisional inference','chain_anchor':anchor,'chain_scope':'Selected records may be a subset of the local ingestion chain.','files':{name:{'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)} for name,body in files.items()}}
            files['manifest.json']=json.dumps(manifest,indent=2).encode()
            files['SHA256SUMS']=('\n'.join(hashlib.sha256(body).hexdigest()+'  '+name for name,body in files.items())+'\n').encode()
            with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
                for name,body in files.items(): z.writestr(name,body)
            sha=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.store.transaction() as db:
                db.execute("UPDATE exports SET status='ready',path=?,sha256=?,manifest=? WHERE id=?",(str(path),sha,canonical(manifest),export_id))
                self.store.audit(db,'analyst','export-ready',export_id,sha); self.store.change(db,'export',export_id)
        except Exception as exc:
            if path.exists(): path.unlink()
            with self.store.transaction() as db:
                db.execute("UPDATE exports SET status='failed',error=? WHERE id=?",(str(exc),export_id)); self.store.change(db,'export',export_id)

    def verify(self,export):
        path=Path(export['path']); checks=[]
        with zipfile.ZipFile(path) as archive:
            manifest=json.loads(archive.read('manifest.json'))
            for name,meta in manifest['files'].items():
                content=archive.read(name)
                checks.append({'file':name,'valid':hashlib.sha256(content).hexdigest()==meta['sha256'] and len(content)==meta['bytes']})
        whole=hashlib.sha256(path.read_bytes()).hexdigest()==export['sha256']
        return {'valid':whole and all(x['valid'] for x in checks),'package_hash_matches_retained_database_anchor':whole,'files':checks,'sha256':export['sha256'],'scope':'Integrity against retained local anchor, not legal authenticity.'}
