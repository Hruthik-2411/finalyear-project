import { useState } from "react";
import { post } from "../api.js";
import { Verdict, useData } from "../ui.jsx";

export default function Audit({ status }) {
  const [d, reload] = useData("/api/audit?limit=150", [], 4000);
  const [ver, setVer] = useState(null);
  const [msg, setMsg] = useState(null);
  const bad = new Set((ver?.problems || []).map((p) => p.seq));

  const verify = () => post("/api/audit/verify").then((v) => { setVer(v); reload(); });
  const seal = () => post("/api/audit/seal").then((r) => { setMsg(r.sealed ? `Sealed events ${r.sealed.from_seq}-${r.sealed.to_seq}` : "Nothing new to seal (or baseline mode)."); reload(); });
  const tamper = () => post("/api/audit/tamper").then((r) => { setMsg(`Edited event #${r.edited_seq} directly in the database. Now verify the ledger.`); reload(); })
    .catch((e) => setMsg(e.message));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Audit trail</h1>
          <p>Every decision is a leaf in a Merkle tree. Each batch root is signed and written to a file outside the database, so
            editing or deleting a row can be detected and pinpointed.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={seal}>Seal now</button>
          <button className="btn danger" onClick={tamper}>Tamper with a row</button>
          <button className="btn primary" onClick={verify}>Verify ledger</button>
          <a className="btn" href="/api/report" target="_blank" rel="noreferrer">Compliance report</a>
        </div>
      </div>
      {msg && <div className="panel small">{msg}</div>}
      {ver && (
        <div className={`panel res ${ver.ok ? "safe" : "hit"}`}>
          <h2>{ver.ok ? (ver.batches ? "Ledger intact" : "Nothing sealed yet") : "Tampering detected"}</h2>
          <p className="small" style={{ marginTop: 4 }}>{ver.batches} sealed batches, {ver.events_checked} events re-hashed, {ver.unsealed} not yet sealed.
            {status?.mode === "baseline" && " Baseline mode keeps a plain log only, so changes cannot be detected."}</p>
          {ver.problems.map((p, i) => <div key={i} className="small">Batch {p.batch}, event {p.seq ?? "-"}: <b>{p.problem}</b></div>)}
        </div>
      )}
      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 320px", marginTop: 16 }}>
        <div className="panel" style={{ padding: 0 }}>
          <div className="scroll" style={{ border: 0, maxHeight: 640 }}>
            <table className="t">
              <thead><tr><th>#</th><th>Time</th><th>Event</th><th>Actor</th><th>Detail</th><th>Leaf hash</th></tr></thead>
              <tbody>{(d?.events || []).map((e) => (
                <tr key={e.seq} style={bad.has(e.seq) ? { background: "var(--block-soft)" } : {}}>
                  <td>{e.seq}{e.seq <= (d?.last_sealed || 0) ? "" : " *"}</td>
                  <td className="small">{e.ts.slice(11, 19)}</td>
                  <td className="small">{e.type}</td>
                  <td className="small">{e.actor}</td>
                  <td className="small">{e.data.verdict && <Verdict v={e.data.verdict} />} {(e.data.receiver || e.data.tool || e.data.agent || "")}
                    {e.data.reason && e.data.verdict !== "APPROVE" && <div className="muted">{String(e.data.reason).slice(0, 100)}</div>}</td>
                  <td className="small muted">{e.leaf.slice(0, 12)}</td>
                </tr>))}</tbody>
            </table>
          </div>
          <p className="small muted" style={{ padding: "8px 12px" }}>* not sealed yet</p>
        </div>
        <div className="panel">
          <h2>Signed roots</h2>
          {!(d?.roots || []).length && <p className="small muted" style={{ marginTop: 8 }}>No roots yet. Roots are sealed every 50 events and at the end of each run (secured mode).</p>}
          {(d?.roots || []).slice().reverse().map((r) => (
            <div key={r.batch} style={{ padding: "8px 0", borderBottom: "1px solid var(--line-2)" }}>
              <b>Batch {r.batch}</b> <span className="small muted">events {r.from_seq}-{r.to_seq}</span>
              <div className="small muted" style={{ wordBreak: "break-all" }}>root {r.root.slice(0, 32)}...</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
