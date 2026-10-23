import { useState } from "react";
import { post } from "../api.js";
import { Trace, Verdict, rupees } from "../ui.jsx";
import { store } from "../store.js";

const SHORTCUTS = [
  ["Check account", "What is the current balance and status of account ACC-1012?"],
  ["Make transfer", "Transfer Rs 25,000 from ACC-1002 to ACC-1012 as requested by the customer."],
  ["Freeze account", "Freeze account ACC-1009 due to suspected card skimming."],
  ["Review loan", "Review loan application LN-002 and tell me its status and credit score."],
  ["Investigate fraud case", "Investigate fraud case FC-010, escalate it and record a case note."],
  ["Look up policy", "Summarise our policy on wire transfer limits for retail customers."],
  ["Unfreeze account", "Unfreeze account ACC-1045; the fraud review is closed and the customer has verified identity."],
];

export default function Operations({ status }) {
  const [req, setReq] = useState(store.lastRequest || SHORTCUTS[0][1]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [run, setRun] = useState(store.lastRun);

  async function go() {
    setBusy(true); setErr(null);
    try {
      const r = await post("/api/run", { request: req });
      store.lastRun = r; store.lastRequest = req; store.selectedRun = r.run_id;
      setRun(r);
    } catch (e) { setErr(e.message); }
    setBusy(false);
  }

  const scope = run?.intent?.scope;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Operations</h1>
          <p>Type a request as bank staff would. Five agents carry it out, and every message and tool call passes the Zero-Trust gateway.</p>
        </div>
      </div>
      <div className="panel">
        <textarea className="req" value={req} onChange={(e) => setReq(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) go(); }} />
        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn primary" onClick={go} disabled={busy || !req.trim()}>
            {busy ? "Running..." : "Run operation"}
          </button>
          <span className="muted small">Ctrl+Enter also runs it. Using {status?.provider} in {status?.mode} mode.</span>
        </div>
        <div className="chips">
          {SHORTCUTS.map(([label, text]) => (
            <button key={label} className="chip" onClick={() => setReq(text)}>{label}</button>
          ))}
        </div>
      </div>
      {err && <div className="panel"><div className="err">{err}</div></div>}
      {run && (
        <>
          <div className="grid g3" style={{ marginTop: 16 }}>
            <div className="panel" style={{ gridColumn: "span 2" }}>
              <div className="panel-head"><h2>Answer</h2><span className="muted small">{run.duration_ms} ms | {run.status}</span></div>
              <div className={`answer ${run.mode === "baseline" ? "base" : ""}`}>{run.final}</div>
              {run.actions?.length > 0 && (
                <table className="t" style={{ marginTop: 14 }}>
                  <thead><tr><th>Action requested by Executor</th><th>Arguments</th><th>Outcome</th></tr></thead>
                  <tbody>{run.actions.map((a, i) => (
                    <tr key={i}><td>{a.tool}</td>
                      <td className="small">{Object.entries(a.args || {}).map(([k, v]) => `${k}: ${k === "amount" ? rupees(v) : v}`).join(", ")}</td>
                      <td><Verdict v={a.verdict} /> {a.status === "pending_approval" && <span className="small muted"> waiting in Approvals</span>}</td></tr>
                  ))}</tbody>
                </table>
              )}
            </div>
            <div className="panel">
              <h2>Signed intent</h2>
              <p className="muted small" style={{ margin: "4px 0 10px" }}>Fixed from your words before any agent read data. Every tool call must fit it.</p>
              {scope ? (
                <table className="t"><tbody>
                  <tr><td>Operation</td><td><b>{scope.operation}</b></td></tr>
                  <tr><td>Writes allowed</td><td>{scope.allowed_writes.length ? scope.allowed_writes.join(", ") : "none"}</td></tr>
                  <tr><td>Entities</td><td className="small">{Object.values(scope.entities).flat().join(", ") || "none"}</td></tr>
                  <tr><td>Max amount</td><td>{scope.max_amount ? rupees(scope.max_amount) : "none"}</td></tr>
                </tbody></table>
              ) : <div className="muted">No intent issued.</div>}
            </div>
          </div>
          <div className="panel" style={{ marginTop: 16 }}>
            <div className="panel-head">
              <h2>Gateway checkpoints</h2>
              <a href="#/graph" className="small">Open delegation graph</a>
            </div>
            <Trace trace={run.trace} mode={run.mode} />
          </div>
          <details className="panel" style={{ marginTop: 16 }}>
            <summary>Agent details: plan, research and audit</summary>
            <div className="grid g2" style={{ marginTop: 12 }}>
              <div><h3>Planner</h3><div className="code">{JSON.stringify(run.plan, null, 2)}</div></div>
              <div><h3>Auditor</h3><div className="code">{JSON.stringify(run.audit, null, 2)}</div></div>
              <div style={{ gridColumn: "1 / -1" }}><h3>Researcher findings</h3><div className="code">{run.findings}</div></div>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
