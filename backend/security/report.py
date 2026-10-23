"""Compliance report: an HTML summary generated from the audit ledger."""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict

from sqlalchemy import select

from backend.common import CLOCK
from backend.db.database import session_scope
from backend.db.models import ApprovalRequest, AuditEvent, Revocation


def build_report(gw) -> str:
    with session_scope() as s:
        events = s.scalars(select(AuditEvent).order_by(AuditEvent.seq)).all()
        verify = gw.ledger.verify(s)
        approvals = s.scalars(select(ApprovalRequest)).all()
        revs = s.scalars(select(Revocation)).all()
        per_agent: dict[str, Counter] = defaultdict(Counter)
        blocked = []
        for e in events:
            if e.event_type != "decision":
                continue
            d = json.loads(e.data)
            per_agent[e.actor][d["verdict"]] += 1
            if d["verdict"] not in ("APPROVE",):
                blocked.append((e.seq, e.ts, e.actor, d.get("receiver"), d["verdict"], d.get("reason", "")))
        types = Counter(e.event_type for e in events)
    esc = html.escape
    verdicts = ["APPROVE", "RESTRICT", "ESCALATE", "BLOCK", "ISOLATE"]
    rows = "".join(f"<tr><td>{esc(a)}</td>" + "".join(f"<td>{c.get(v, 0)}</td>" for v in verdicts) + "</tr>"
                   for a, c in sorted(per_agent.items()))
    brows = "".join(f"<tr><td>{q}</td><td>{esc(t[:19])}</td><td>{esc(a)}</td><td>{esc(str(r))}</td><td>{v}</td>"
                    f"<td>{esc(why[:160])}</td></tr>" for q, t, a, r, v, why in blocked[-200:])
    probs = "".join(f"<li>batch {p['batch']}, event {p.get('seq')}: {esc(p['problem'])}</li>" for p in verify["problems"])
    trust = gw.trust.snapshot()
    trows = "".join(f"<tr><td>{a}</td><td>{v['score']:.2f}</td><td>{v['ceiling']:.2f}</td></tr>" for a, v in trust.items())
    arows = "".join(f"<tr><td>{esc(x.id)}</td><td>{esc(x.tool)}</td><td>{esc(x.args[:80])}</td><td>{x.status}</td>"
                    f"<td>{esc(x.reason[:120])}</td></tr>" for x in approvals)
    rv = "".join(f"<li>{esc(r.agent)} (serial {r.serial[:12]}...) - {esc(r.reason[:150])}</li>" for r in revs) or "<li>none</li>"
    status = ("<b style='color:#0a7d33'>INTACT</b>" if verify["ok"] else "<b style='color:#c62828'>TAMPERING DETECTED</b>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>FinSecure Compliance Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1d1d1b;max-width:1100px}}
table{{border-collapse:collapse;margin:8px 0 24px;width:100%}}td,th{{border:1px solid #ddd;padding:6px 8px;font-size:13px;text-align:left}}
th{{background:#f3f2ef}}h1{{margin-bottom:4px}}.muted{{color:#666}}</style></head><body>
<h1>FinSecure Compliance Report</h1><div class="muted">Generated {CLOCK.iso()} | mode: {gw.mode}</div>
<h2>1. Audit ledger integrity: {status}</h2>
<p>{verify['batches']} sealed Merkle batches, {verify['events_checked']} events verified, {verify['unsealed']} events not yet sealed.</p>
<ul>{probs or '<li>No problems found.</li>'}</ul>
<h2>2. Gateway decisions per agent</h2><table><tr><th>Agent</th>{''.join(f'<th>{v}</th>' for v in verdicts)}</tr>{rows}</table>
<h2>3. Current trust scores</h2><table><tr><th>Agent</th><th>Trust</th><th>Recovery ceiling</th></tr>{trows}</table>
<h2>4. Isolated agents (revoked certificates)</h2><ul>{rv}</ul>
<h2>5. Human approval requests</h2><table><tr><th>ID</th><th>Tool</th><th>Args</th><th>Status</th><th>Reason</th></tr>{arows}</table>
<h2>6. Non-approved actions (latest 200)</h2><table><tr><th>#</th><th>Time</th><th>Agent</th><th>Target</th><th>Verdict</th><th>Reason</th></tr>{brows}</table>
<h2>7. Event counts</h2><p>{', '.join(f'{k}: {v}' for k, v in types.items())}</p>
</body></html>"""
