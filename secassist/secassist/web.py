"""Einfache Web-Oberfläche: Prüfung starten, live mitlesen, Aktionen freigeben, Bericht ansehen.

Start: SECASSIST_UI_TOKEN=... secassist web --scope scope.yaml
Läuft standardmäßig nur auf 127.0.0.1. Für Team-Nutzung hinter einen Reverse-Proxy mit TLS + SSO stellen.
"""
from __future__ import annotations

import hmac
import os
import threading
import uuid
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from .agent import run_assessment
from .report import render
from .scope import Scope

app = FastAPI(title="secassist")
APPROVAL_TIMEOUT = 30 * 60  # Sekunden; danach gilt eine Aktion als abgelehnt


@dataclass
class Session:
    id: str
    mode: str
    target: str
    events: list[dict] = field(default_factory=list)
    pending: dict[str, dict] = field(default_factory=dict)
    report: str = ""
    status: str = "läuft"
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, kind: str, data: dict) -> None:
        with self.lock:
            self.events.append({"n": len(self.events), "kind": kind, **data})


SESSIONS: dict[str, Session] = {}


def require_token(x_token: str = Header(default="")) -> None:
    expected = os.environ.get("SECASSIST_UI_TOKEN", "")
    if not expected or not hmac.compare_digest(x_token, expected):
        raise HTTPException(status_code=401, detail="Ungültiges Token")


class StartRequest(BaseModel):
    mode: str
    target: str
    instructions: str = ""
    effort: str = "high"


class Decision(BaseModel):
    approval_id: str
    approved: bool


def _worker(sess: Session, req: StartRequest) -> None:
    scope = Scope.load(os.environ["SECASSIST_SCOPE"])

    def approve(summary: str, details: dict) -> bool:
        aid = uuid.uuid4().hex[:8]
        waiter = {"event": threading.Event(), "approved": False}
        with sess.lock:
            sess.pending[aid] = waiter
        sess.add("approval_request", {"approval_id": aid, "summary": summary})
        answered = waiter["event"].wait(APPROVAL_TIMEOUT)
        with sess.lock:
            sess.pending.pop(aid, None)
        sess.add("approval_decision", {"approval_id": aid, "approved": answered and waiter["approved"]})
        return answered and waiter["approved"]

    try:
        result = run_assessment(scope, req.mode, req.target, req.instructions, approve=approve, on_event=sess.add,
                                log_dir=os.environ.get("SECASSIST_LOG_DIR", "logs"), effort=req.effort,
                                session_id=sess.id)
        sess.report = render(scope, req.mode, req.target, result.findings, result.summary, result.session_id,
                             result.audit_path)
        report_dir = os.environ.get("SECASSIST_REPORT_DIR", "reports")
        os.makedirs(report_dir, exist_ok=True)
        with open(os.path.join(report_dir, f"bericht-{sess.id}.md"), "w", encoding="utf-8") as f:
            f.write(sess.report)
        sess.status = "fertig"
    except Exception as e:  # noqa: BLE001 – Fehler in der UI anzeigen statt Thread still sterben lassen
        sess.add("error", {"text": f"{type(e).__name__}: {e}"})
        sess.status = "Fehler"


@app.get("/api/scope", dependencies=[Depends(require_token)], response_class=PlainTextResponse)
def get_scope() -> str:
    return Scope.load(os.environ["SECASSIST_SCOPE"]).summary()


@app.post("/api/sessions", dependencies=[Depends(require_token)])
def start(req: StartRequest) -> dict:
    if req.mode not in ("code", "web", "infra"):
        raise HTTPException(400, "mode muss code, web oder infra sein")
    sess = Session(id=uuid.uuid4().hex[:12], mode=req.mode, target=req.target)
    SESSIONS[sess.id] = sess
    threading.Thread(target=_worker, args=(sess, req), daemon=True).start()
    return {"session_id": sess.id}


@app.get("/api/sessions/{sid}", dependencies=[Depends(require_token)])
def poll(sid: str, after: int = -1) -> dict:
    sess = SESSIONS.get(sid) or _not_found()
    with sess.lock:
        events = [e for e in sess.events if e["n"] > after]
    return {"status": sess.status, "events": events, "has_report": bool(sess.report)}


@app.post("/api/sessions/{sid}/approve", dependencies=[Depends(require_token)])
def decide(sid: str, d: Decision) -> dict:
    sess = SESSIONS.get(sid) or _not_found()
    with sess.lock:
        waiter = sess.pending.get(d.approval_id)
    if not waiter:
        raise HTTPException(404, "Keine offene Freigabe mit dieser ID")
    waiter["approved"] = d.approved
    waiter["event"].set()
    return {"ok": True}


@app.get("/api/sessions/{sid}/report", dependencies=[Depends(require_token)], response_class=PlainTextResponse)
def report(sid: str) -> str:
    sess = SESSIONS.get(sid) or _not_found()
    return sess.report


def _not_found():
    raise HTTPException(404, "Sitzung nicht gefunden")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


INDEX_HTML = r"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>secassist</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e2e2dc;--accent:#2f5bd3;--ok:#1f7a3f;--bad:#b3261e;--warn:#9a6b00}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ececea;--muted:#9c9c96;--card:#1f1f1e;--line:#33332f;--accent:#7d9cf0;--ok:#5cc184;--bad:#f08a80;--warn:#e0b350}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
label{display:block;font-size:13px;color:var(--muted);margin:8px 0 4px}
input,select,textarea{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
button{padding:8px 14px;border-radius:6px;border:1px solid var(--line);background:var(--accent);color:#fff;font:inherit;cursor:pointer}
button.no{background:var(--bad)}button.yes{background:var(--ok)}pre{white-space:pre-wrap;word-break:break-word;margin:0;font-size:13px}
.ev{border-top:1px solid var(--line);padding:8px 0}.ev .k{font-size:12px;color:var(--muted)}
.thinking pre{color:var(--muted)}.approval{border:2px solid var(--warn);border-radius:8px;padding:10px;margin:8px 0}
.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1;min-width:140px}
</style></head><body><main>
<h1>secassist – Sicherheits-Assistent</h1>
<div class="card"><label>Zugangstoken</label><input id="token" type="password" autocomplete="off">
<label>Scope</label><pre id="scope">(Token eingeben und „Scope laden“)</pre><br><button id="loadScope">Scope laden</button></div>
<div class="card">
<div class="row"><div><label>Modus</label><select id="mode"><option value="code">Code</option><option value="web">Web/API</option><option value="infra">Infrastruktur</option></select></div>
<div><label>Aufwand</label><select id="effort"><option>medium</option><option selected>high</option><option>xhigh</option></select></div></div>
<label>Ziel (Code-Pfad, URL, Host oder Netz)</label><input id="target">
<label>Hinweise (Fokus, Test-Accounts …)</label><textarea id="instr" rows="3"></textarea><br><br>
<label><input type="checkbox" id="confirm" style="width:auto"> Für dieses Ziel liegt eine schriftliche Freigabe vor</label><br>
<button id="start">Prüfung starten</button></div>
<div class="card"><div class="k" id="status">Keine Sitzung</div><div id="events"></div></div>
<div class="card"><button id="showReport">Bericht anzeigen</button><pre id="report"></pre></div>
</main><script>
let sid=null,last=-1,timer=null;
const $=id=>document.getElementById(id);
try{$('token').value=sessionStorage.getItem('tok')||''}catch(e){}
function hdr(){try{sessionStorage.setItem('tok',$('token').value)}catch(e){}return{'X-Token':$('token').value,'Content-Type':'application/json'}}
async function api(p,o={}){const r=await fetch(p,{...o,headers:hdr()});if(!r.ok)throw new Error(r.status+' '+await r.text());return r}
$('loadScope').onclick=async()=>{try{$('scope').textContent=await (await api('/api/scope')).text()}catch(e){$('scope').textContent=e.message}};
$('start').onclick=async()=>{
 if(!$('confirm').checked){alert('Bitte Freigabe bestätigen.');return}
 const body={mode:$('mode').value,target:$('target').value,instructions:$('instr').value,effort:$('effort').value};
 try{const r=await (await api('/api/sessions',{method:'POST',body:JSON.stringify(body)})).json();sid=r.session_id;last=-1;$('events').textContent='';clearInterval(timer);timer=setInterval(poll,1500);poll()}catch(e){alert(e.message)}};
function add(kind,text,cls){const d=document.createElement('div');d.className='ev '+(cls||'');const k=document.createElement('div');k.className='k';k.textContent=kind;const p=document.createElement('pre');p.textContent=text;d.append(k,p);$('events').prepend(d);return d}
async function decide(aid,ok,box){await api('/api/sessions/'+sid+'/approve',{method:'POST',body:JSON.stringify({approval_id:aid,approved:ok})});box.querySelectorAll('button').forEach(b=>b.remove())}
async function poll(){if(!sid)return;let r;try{r=await (await api('/api/sessions/'+sid+'?after='+last)).json()}catch(e){return}
 $('status').textContent='Sitzung '+sid+' – '+r.status;
 for(const e of r.events){last=e.n;
  if(e.kind==='thinking')add('denkt',e.text,'thinking');
  else if(e.kind==='text')add('Antwort',e.text);
  else if(e.kind==='tool_call')add('Werkzeug: '+e.name,JSON.stringify(e.input,null,2));
  else if(e.kind==='tool_result')add((e.is_error?'Fehler ':'Ergebnis ')+e.name,e.result);
  else if(e.kind==='approval_request'){const d=add('FREIGABE ERFORDERLICH',e.summary,'approval');const y=document.createElement('button');y.className='yes';y.textContent='Ausführen';const n=document.createElement('button');n.className='no';n.textContent='Ablehnen';y.onclick=()=>decide(e.approval_id,true,d);n.onclick=()=>decide(e.approval_id,false,d);const row=document.createElement('div');row.className='row';row.append(y,n);d.append(row)}
  else if(e.kind==='approval_decision')add('Entscheidung',e.approved?'freigegeben':'abgelehnt');
  else add(e.kind,JSON.stringify(e))}
 if(r.status!=='läuft')clearInterval(timer)}
$('showReport').onclick=async()=>{if(!sid)return;try{$('report').textContent=await (await api('/api/sessions/'+sid+'/report')).text()}catch(e){$('report').textContent=e.message}};
</script></body></html>"""
