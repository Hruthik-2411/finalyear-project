import { post } from "../api.js";
import { Verdict, rupees, useData } from "../ui.jsx";

export default function Approvals() {
  const [rows, reload] = useData("/api/approvals", [], 3000);
  const pending = (rows || []).filter((r) => r.status === "PENDING");
  const done = (rows || []).filter((r) => r.status !== "PENDING");
  const decide = (id, approve) => post(`/api/approvals/${id}`, { approve }).then(reload);
  const fmt = (args) => Object.entries(args).map(([k, v]) => `${k}: ${k === "amount" ? rupees(v) : v}`).join(", ");
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Pending reviews</h1>
          <p>Irreversible actions the gateway held for a person: low agent trust, a chain that touched flagged data, or a policy
            that requires an officer. Approving runs the action after the policy check is repeated.</p>
        </div>
      </div>
      <div className="panel">
        <h2>Waiting ({pending.length})</h2>
        {!pending.length ? <div className="empty">Nothing is waiting for review.</div> : (
          <table className="t" style={{ marginTop: 10 }}>
            <thead><tr><th>Requested by</th><th>Action</th><th>Why it was held</th><th></th></tr></thead>
            <tbody>{pending.map((r) => (
              <tr key={r.id}>
                <td>{r.agent}<div className="small muted">{r.created.slice(11, 19)}</div></td>
                <td><b>{r.tool}</b><div className="small">{fmt(r.args)}</div></td>
                <td className="small">{r.reason}</td>
                <td><div className="row">
                  <button className="btn primary small" onClick={() => decide(r.id, true)}>Approve</button>
                  <button className="btn danger small" onClick={() => decide(r.id, false)}>Reject</button>
                </div></td>
              </tr>))}</tbody>
          </table>
        )}
      </div>
      <div className="panel">
        <h2>Decided</h2>
        {!done.length ? <p className="muted small" style={{ marginTop: 8 }}>No decisions yet.</p> : (
          <table className="t" style={{ marginTop: 10 }}>
            <thead><tr><th>Action</th><th>Outcome</th><th>Result</th></tr></thead>
            <tbody>{done.map((r) => (
              <tr key={r.id}><td><b>{r.tool}</b><div className="small">{fmt(r.args)}</div></td>
                <td><Verdict v={r.status === "APPROVED" ? "APPROVE" : "BLOCK"} /> <span className="small">{r.status.toLowerCase()}</span></td>
                <td className="small">{String(r.result).slice(0, 160)}</td></tr>))}</tbody>
          </table>
        )}
      </div>
    </div>
  );
}
