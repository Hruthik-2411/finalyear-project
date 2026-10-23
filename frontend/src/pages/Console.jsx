import { useState } from "react";
import { CheckStrip, useEvents } from "../ui.jsx";

export default function Console({ status }) {
  const [items, setItems] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState("all");

  useEvents((e) => {
    if (e.type === "envelope") setItems((x) => [e.data, ...x].slice(0, 300));
    if (e.type === "alert") setAlerts((x) => [{ ...e.data, ts: e.ts }, ...x].slice(0, 50));
    if (e.type === "reset") { setItems([]); setAlerts([]); }
  });

  const shown = items.filter((t) => filter === "all" || (filter === "stopped" ? t.verdict !== "APPROVE" : t.kind === filter));
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Security console</h1>
          <p>Every envelope the gateway handles, newest first, live. Hover a check to see why it passed or failed.</p>
        </div>
        <div className="row">
          {[["all", "All"], ["tool_call", "Tool calls"], ["message", "Messages"], ["stopped", "Not approved"]].map(([k, l]) => (
            <button key={k} className={`chip ${filter === k ? "on" : ""}`} style={filter === k ? { borderColor: "var(--vault)", color: "var(--vault)" } : {}}
                    onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) 300px" }}>
        <div className="panel" style={{ padding: 0 }}>
          {shown.length ? shown.map((t, i) => <CheckStrip key={t.msg_id + i} t={t} mode={status?.mode} />) :
            <div className="empty">Waiting for traffic. Run an operation or an Attack Lab scenario, and envelopes appear here as the gateway decides on them.</div>}
        </div>
        <div className="panel">
          <h2>Alerts</h2>
          {!alerts.length && <p className="muted small" style={{ marginTop: 8 }}>No alerts. Injection flags, impersonation attempts and isolations show up here.</p>}
          {alerts.map((a, i) => (
            <div key={i} style={{ borderTop: i ? "1px solid var(--line-2)" : 0, padding: "10px 0" }}>
              <b style={{ color: a.type === "isolation" ? "var(--isolate)" : "var(--block)" }}>
                {a.type === "prompt_injection" ? "Prompt injection flagged" : a.type === "isolation" ? `Agent isolated: ${a.agent}` :
                  a.type === "impersonation" ? `Impersonation of ${a.claimed}` : a.type}
              </b>
              <div className="small muted">{a.ts?.slice(11, 19)}</div>
              <div className="small" style={{ marginTop: 4 }}>
                {a.reason || a.detail || (a.flags && a.flags.map((f) => `${f.level} risk ${f.score} in ${a.tool}: "${f.excerpt.slice(0, 90)}..."`).join(" "))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
