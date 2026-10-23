import { useEffect, useState } from "react";
import { get } from "../api.js";
import { useData } from "../ui.jsx";
import { store } from "../store.js";

const LANES = ["gateway", "orchestrator", "planner", "researcher", "executor", "auditor", "tools"];
const VCOL = { APPROVE: "#1a7f37", ESCALATE: "#a15c00", BLOCK: "#c62828", ISOLATE: "#6d28d9", RESTRICT: "#475569",
  ISSUED: "#2554a8", LOG: "#c2410c", "": "#718096" };

export default function Graph() {
  const [runs] = useData("/api/runs?limit=40");
  const [sel, setSel] = useState(store.selectedRun);
  const [dag, setDag] = useState(null);
  const [hover, setHover] = useState(null);

  useEffect(() => { if (!sel && runs && runs.length) setSel(runs[0].id); }, [runs]);
  useEffect(() => { if (sel) get(`/api/dag/${sel}`).then(setDag).catch(() => setDag(null)); }, [sel]);

  const nodes = dag?.nodes || [];
  const colW = 64, laneH = 54, left = 120, topPad = 30;
  const W = Math.max(760, left + nodes.length * colW + 40), H = topPad + LANES.length * laneH + 24;
  const laneY = (name) => topPad + LANES.indexOf(name.startsWith("tool:") ? "tools" : LANES.includes(name) ? name : "tools") * laneH + laneH / 2;
  const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Delegation graph</h1>
          <p>Each column is one envelope, in order. Arrows go from the sender to the receiver and are coloured by the gateway's verdict.
            Every envelope names its parent, so any tool call can be traced back to the signed intent at the far left.</p>
        </div>
        <select className="search" value={sel || ""} onChange={(e) => setSel(e.target.value)}>
          {(runs || []).map((r) => <option key={r.id} value={r.id}>{r.started?.slice(11, 19)} | {r.mode} | {r.request.slice(0, 60)}</option>)}
        </select>
      </div>
      <div className="panel" style={{ overflowX: "auto", position: "relative" }}>
        {!nodes.length ? <div className="empty">Run an operation first; its delegation graph appears here.</div> : (
          <svg width={W} height={H} role="img" aria-label="Delegation graph of the selected run">
            <defs>
              {Object.entries(VCOL).map(([k, c]) => (
                <marker key={k} id={`ar-${k || "none"}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M0 0L10 5L0 10z" fill={c} />
                </marker>
              ))}
            </defs>
            {LANES.map((l, i) => (
              <g key={l}>
                <line x1={left - 10} x2={W - 10} y1={topPad + i * laneH + laneH / 2} y2={topPad + i * laneH + laneH / 2} stroke="#eef1f5" />
                <text x={12} y={topPad + i * laneH + laneH / 2 + 4} fontSize="12.5" fontWeight="600" fill="#13233f">{l}</text>
              </g>
            ))}
            {/* parent links (dashed) */}
            {(dag.edges || []).map((e, i) => idx[e.from] !== undefined && idx[e.to] !== undefined && (
              <path key={i} d={`M${left + idx[e.from] * colW + 20} ${laneY(nodes[idx[e.from]].receiver)} C ${left + idx[e.from] * colW + 40} ${laneY(nodes[idx[e.from]].receiver)}, ${left + idx[e.to] * colW} ${laneY(nodes[idx[e.to]].sender)}, ${left + idx[e.to] * colW + 20} ${laneY(nodes[idx[e.to]].sender)}`}
                    fill="none" stroke="#cbd3df" strokeDasharray="3 3" />
            ))}
            {nodes.map((n, i) => {
              const x = left + i * colW + 20, y1 = laneY(n.sender), y2 = laneY(n.receiver);
              const c = VCOL[n.verdict] || VCOL[""];
              return (
                <g key={n.id} onMouseEnter={() => setHover({ n, x, y: Math.min(y1, y2) })} onMouseLeave={() => setHover(null)}>
                  <line x1={x} x2={x} y1={y1} y2={y2 === y1 ? y1 + 1 : y2 + (y2 > y1 ? -6 : 6)} stroke={c} strokeWidth="2.5"
                        markerEnd={`url(#ar-${n.verdict || "none"})`} />
                  <circle cx={x} cy={y1} r="5" fill={c} stroke="#fff" strokeWidth="2" />
                  {n.kind === "tool_call" && <text x={x} y={y2 + 16 + (i % 2) * 13} fontSize="10.5" textAnchor="middle" fill="#4a5568">{n.label.replace("tool:", "").replace(/_/g, " ").slice(0, 14)}</text>}
                  <rect x={x - 14} y={Math.min(y1, y2) - 8} width="28" height={Math.abs(y2 - y1) + 16} fill="transparent" />
                </g>
              );
            })}
          </svg>
        )}
        {hover && (
          <div className="tip" style={{ left: hover.x + 18, top: hover.y + 20 }}>
            {hover.n.sender} to {hover.n.receiver} | {hover.n.verdict} | node {hover.n.hash}
          </div>
        )}
      </div>
      <div className="legend">
        {Object.entries(VCOL).filter(([k]) => k).map(([k, c]) => <span key={k}><i style={{ background: c }} />{k}</span>)}
        <span><i style={{ background: "#cbd3df" }} />parent link</span>
      </div>
    </div>
  );
}
