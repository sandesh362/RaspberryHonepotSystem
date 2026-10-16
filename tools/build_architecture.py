"""Build the architecture PDF, editable Markdown, and vector overview.

Run from any directory: python tools/build_architecture.py
Content lives in docs/architecture.json. No network or project runtime required.
"""
from pathlib import Path
import json
from html import escape
import importlib.metadata

from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, Frame, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.graphics import renderSVG
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / 'docs/architecture.json').read_text(encoding='utf-8'))
OUT = ROOT / 'output/pdf/honeypot-system-architecture.pdf'
W, H = A4
M = 43
CW = W - 2*M
NAVY = colors.HexColor('#122A3A')
TEAL = colors.HexColor('#007E80')
INK = colors.HexColor('#243D4B')
MUTED = colors.HexColor('#526773')
LIGHT = colors.HexColor('#EDF4F5')
LINE = colors.HexColor('#D4E0E4')
WHITE = colors.white


def para(text, style):
    return Paragraph(escape(text), style)


def styles(scale=1):
    return {
        'body': ParagraphStyle('body', fontName='Helvetica', fontSize=9.3*scale,
                               leading=13.5*scale, textColor=INK, spaceAfter=7*scale),
        'heading': ParagraphStyle('heading', fontName='Helvetica-Bold', fontSize=10.3*scale,
                                  leading=13.5*scale, textColor=NAVY, spaceAfter=4*scale),
        'intro': ParagraphStyle('intro', fontName='Helvetica', fontSize=11*scale,
                                leading=15.5*scale, textColor=MUTED, spaceAfter=12*scale),
        'cell': ParagraphStyle('cell', fontName='Helvetica', fontSize=8.8*scale,
                               leading=12.2*scale, textColor=INK),
        'headcell': ParagraphStyle('headcell', fontName='Helvetica-Bold', fontSize=8.8*scale,
                                   leading=12*scale, textColor=WHITE),
        'small': ParagraphStyle('small', fontName='Helvetica', fontSize=8.4*scale,
                                leading=11.5*scale, textColor=MUTED, spaceAfter=7*scale),
    }


def box(d, x, y, w, h, title, lines, fill=LIGHT, title_color=NAVY):
    d.add(Rect(x,y,w,h,rx=5,fillColor=fill,strokeColor=LINE,strokeWidth=.7))
    d.add(String(x+11,y+h-20,title,fontName='Helvetica-Bold',fontSize=10,fillColor=title_color))
    for i,line in enumerate(lines):
        d.add(String(x+11,y+h-36-i*13,line,fontName='Helvetica',fontSize=8.6,fillColor=INK))


def arrow(d, x1,y1,x2,y2):
    d.add(Line(x1,y1,x2,y2,strokeColor=TEAL,strokeWidth=1.4))
    if abs(x2-x1)>abs(y2-y1):
        direction=1 if x2>x1 else -1
        pts=[x2,y2,x2-direction*6,y2+3,x2-direction*6,y2-3]
    else:
        direction=1 if y2>y1 else -1
        pts=[x2,y2,x2-3,y2-direction*6,x2+3,y2-direction*6]
    d.add(Polygon(pts,fillColor=TEAL,strokeColor=TEAL))


def topology():
    d=Drawing(CW,313)
    box(d,0,252,CW,54,'AUTHORIZED LAB CLIENT', ['Bounded scan, fake authentication and inert shell / HTTP requests'])
    d.add(Rect(0,94,235,140,rx=5,fillColor=WHITE,strokeColor=LINE))
    d.add(Rect(265,94,CW-265,140,rx=5,fillColor=WHITE,strokeColor=LINE))
    d.add(String(11,216,'RASPBERRY PI / SENSOR',fontName='Helvetica-Bold',fontSize=10,fillColor=TEAL))
    d.add(String(276,216,'LAPTOP / CONTROL PLANE',fontName='Helvetica-Bold',fontSize=10,fillColor=TEAL))
    box(d,11,151,213,52,'Cowrie + HTTP decoy',['Suricata observes traffic reaching eth0'])
    box(d,11,105,213,38,'Collector + local spool',[])
    box(d,276,151,CW-287,52,'FastAPI + analysis worker',['Rules / ML; SQLite + raw archive'])
    box(d,276,105,CW-287,38,'Authenticated API + SSE',[])
    arrow(d,117,252,117,234)
    arrow(d,117,151,117,143)
    d.add(Line(224,124,250,124,strokeColor=TEAL,strokeWidth=1.4))
    d.add(Line(250,124,250,177,strokeColor=TEAL,strokeWidth=1.4))
    arrow(d,250,177,276,177)
    d.add(String(237,147,'TLS',fontName='Helvetica-Bold',fontSize=8,fillColor=TEAL))
    arrow(d,381,151,381,143)
    box(d,0,5,CW,61,'REACT DASHBOARD + EVIDENCE EXPORT',
        ['Live events and sessions; findings with reasons; sensor health',
         'Case PDF + ZIP; hashes and collection history; explicit LIVE / REPLAY mode'])
    arrow(d,381,94,381,66)
    return d


def pipeline():
    d=Drawing(CW,118)
    labels=[('OBSERVE',['Decoy / network']),('PRESERVE',['Raw + spool']),('COMMIT',['Validate / dedup']),('EXPLAIN',['Rules / ML']),('PRESENT',['SSE / evidence'])]
    bw=(CW-32)/5
    for i,(title,lines) in enumerate(labels):
        x=i*(bw+8)
        box(d,x,42,bw,68,title,lines)
        if i<4: arrow(d,x+bw,76,x+bw+8,76)
    d.add(String(0,20,'Acknowledgement follows durable storage. UI updates follow committed findings.',
                 fontName='Helvetica',fontSize=9,fillColor=MUTED))
    return d


def table(rows, st, scale):
    body=[]
    for i,row in enumerate(rows):
        body.append([para(t,st['headcell'] if i==0 else st['cell']) for t in row])
    t=Table(body,colWidths=[CW*.265,CW*.735],hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),NAVY),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,LIGHT]),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
        ('TOPPADDING',(0,0),(-1,-1),7*scale),('BOTTOMPADDING',(0,0),(-1,-1),7*scale),
        ('LINEBELOW',(0,-1),(-1,-1),.5,LINE),
    ]))
    return t


def link_paragraph(url, st):
    # Break opportunities preserve a clickable URL while avoiding margin overflow.
    label=escape(url).replace('/', '/<wbr/>').replace('.', '.<wbr/>')
    return Paragraph(f'<link href="{escape(url, quote=True)}" color="#007E80">{label}</link>',st)


def story(page, scale):
    st=styles(scale)
    items=[]
    if page['kicker'].startswith('01'):
        items.append(para(DATA['subtitle'],st['heading']))
    if page.get('intro'): items.append(para(page['intro'],st['intro']))
    if page.get('diagram'):
        items += [topology() if page['diagram']=='topology' else pipeline(),Spacer(1,10)]
    if page.get('rows'): items += [table(page['rows'],st,scale),Spacer(1,12*scale)]
    for refid in page.get('references',[]):
        r=next(x for x in DATA['sources'] if x['id']==refid)
        items.append(para(f"[{refid}] {r['title']}",st['heading']))
        items.append(link_paragraph(r['url'],st['small']))
        if r.get('extra'): items.append(link_paragraph(r['extra'],st['small']))
        items += [para(r['why'],st['body']),Spacer(1,5*scale)]
    for block in page.get('blocks',[]):
        items.extend([para(block['h'],st['heading']),para(block['p'],st['body']),Spacer(1,5*scale)])
    if page.get('callout'):
        c=Table([[para(page['callout'],st['heading'])]],colWidths=[CW])
        c.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LIGHT),('BOX',(0,0),(-1,-1),.5,LINE),
                              ('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),
                              ('TOPPADDING',(0,0),(-1,-1),11),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
        items += [Spacer(1,5),c]
    return items


def furniture(c,page,num):
    c.setFillColor(TEAL)
    c.rect(M,H-42,30,3,fill=1,stroke=0)
    c.setFont('Helvetica-Bold',8)
    c.drawString(M+40,H-42,'HONEYPOT / SYSTEM ARCHITECTURE')
    c.setFillColor(MUTED)
    c.setFont('Helvetica',8)
    c.drawRightString(W-M,H-42,'B.E. MAJOR PROJECT / 2026-27')
    c.setFillColor(TEAL)
    c.setFont('Helvetica-Bold',8)
    c.drawString(M,H-76,page['kicker'])
    title_st=ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=22,leading=26,textColor=NAVY)
    p=para(page['title'],title_st)
    _,th=p.wrap(CW,100)
    p.drawOn(c,M,H-91-th)
    c.setStrokeColor(LINE)
    c.line(M,42,W-M,42)
    c.setFillColor(MUTED)
    c.setFont('Helvetica',7.5)
    c.drawString(M,28,'Architecture v1.0 | 16 October 2026 | Proposed, not yet implemented')
    c.drawRightString(W-M,28,f'{num:02d} / {len(DATA["pages"]):02d}')
    return H-108-th


def write_markdown():
    lines=[f'# {DATA["title"]}',f'\n{DATA["subtitle"]}',f'\n{DATA["status"]} | {DATA["date"]}',
           f'\nRepository: [{DATA["repository"]}]({DATA["repository"]})',
           '\nEditable architecture content: `docs/architecture.json`. Rebuild with `python tools/build_architecture.py`.',
           '\n[Download the architecture PDF](../output/pdf/honeypot-system-architecture.pdf)',
           '\n[Mermaid architecture source](diagrams/architecture.mmd)']
    for page in DATA['pages']:
        lines += [f'\n## {page["kicker"]}: {page["title"]}\n']
        if page.get('intro'): lines += [page['intro']+'\n']
        if page.get('diagram')=='topology': lines += ['![System overview](diagrams/architecture.svg)\n']
        if page.get('diagram')=='pipeline': lines += ['Observe → Preserve → Commit → Explain → Present\n']
        if page.get('rows'):
            rows=page['rows']
            lines += ['| '+' | '.join(rows[0])+' |','| '+ ' | '.join(['---']*len(rows[0]))+' |']
            lines += ['| '+' | '.join(r)+' |' for r in rows[1:]]
            lines += ['']
        for b in page.get('blocks',[]): lines += [f'### {b["h"]}\n',b['p']+'\n']
        if page.get('callout'): lines += ['> '+page['callout']+'\n']
        for refid in page.get('references',[]):
            r=next(x for x in DATA['sources'] if x['id']==refid)
            lines += [f'[{refid}] [{r["title"]}]({r["url"]}) - {r["why"]}\n']
            if r.get('extra'): lines += [f'Additional reference: [documentation]({r["extra"]})\n']
    (ROOT/'docs/architecture.md').write_text('\n'.join(lines).rstrip()+'\n',encoding='utf-8')


def build():
    OUT.parent.mkdir(parents=True,exist_ok=True)
    # Dry-run frames select a readable fit before drawing the real PDF.
    selected=[]
    for num,page in enumerate(DATA['pages'],1):
        fit=None
        for scale in [1,.97,.94,.91,.88]:
            probe=canvas.Canvas(str(ROOT/'tmp/pdfs/layout-probe.pdf'),pagesize=A4)
            top=furniture(probe,page,num)
            flow=story(page,scale)
            f=Frame(M,55,CW,top-55,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)
            f.addFromList(flow,probe)
            if not flow:
                fit=scale
                break
        if fit is None: raise RuntimeError(f'Page {num} overflows even at minimum readable scale')
        selected.append(fit)
    c=canvas.Canvas(str(OUT),pagesize=A4,pageCompression=1)
    c.setTitle(DATA['title']+' - Architecture')
    c.setAuthor('RaspberryHonepotSystem project')
    c.setSubject('Architecture proposal, implementation phases and live evaluation plan')
    for num,(page,scale) in enumerate(zip(DATA['pages'],selected),1):
        top=furniture(c,page,num)
        flow=story(page,scale)
        f=Frame(M,55,CW,top-55,leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)
        f.addFromList(flow,c)
        if flow: raise RuntimeError(f'Unexpected layout overflow on page {num}')
        c.bookmarkPage(f'page-{num}')
        c.addOutlineEntry(page['title'],f'page-{num}',level=0)
        c.showPage()
    c.save()
    renderSVG.drawToFile(topology(),str(ROOT/'docs/diagrams/architecture.svg'))
    write_markdown()
    r=PdfReader(OUT)
    assert len(r.pages)==len(DATA['pages'])
    for i,(page,pdfpage) in enumerate(zip(DATA['pages'],r.pages),1):
        text=pdfpage.extract_text()
        assert page['title'] in text.replace('\n',' '),(i,'missing title')
        for b in page.get('blocks',[]):
            assert b['h'] in text.replace('\n',' '),(i,'missing block',b['h'])
        assert '\ufffd' not in text,(i,'replacement glyph')
    print(json.dumps({'pdf':str(OUT),'pages':len(r.pages),'page_font_scales':selected,
                      'reportlab':importlib.metadata.version('reportlab'),
                      'pypdf':importlib.metadata.version('pypdf')},indent=2))


if __name__=='__main__':
    (ROOT/'tmp/pdfs').mkdir(parents=True,exist_ok=True)
    build()
