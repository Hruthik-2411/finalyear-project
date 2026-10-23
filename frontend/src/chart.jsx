import { useState } from "react";

export const SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"];

/** Minimal line chart: series = [{name, color, points:[{x,y}]}], horizontal threshold bands. */
export function LineChart({ series: raw, height = 300, yMax = 1, xLabel = "", thresholds = [], step = true }) {
  const [hx, setHx] = useState(null);
  const W = 860, H = height, L = 44, R = 120, T = 14, B = 34;
  const all = raw.flatMap((s) => s.points);
  if (!all.length) return <div className="empty">No data yet.</div>;
  const x0 = Math.min(...all.map((p) => p.x)), x1 = Math.max(...all.map((p) => p.x), x0 + 1e-6);
  // carry every series flat to the right edge so all lines span the chart
  const series = raw.map((s) => s.points.length && s.points[s.points.length - 1].x < x1
    ? { ...s, points: [...s.points, { x: x1, y: s.points[s.points.length - 1].y }] } : s);
  const X = (x) => L + ((x - x0) / (x1 - x0 || 1)) * (W - L - R);
  const Y = (y) => T + (1 - y / yMax) * (H - T - B);
  const path = (pts) => pts.map((p, i) => {
    if (i === 0) return `M${X(p.x)},${Y(p.y)}`;
    return step ? `H${X(p.x)}V${Y(p.y)}` : `L${X(p.x)},${Y(p.y)}`;
  }).join("");
  const ticks = [0, 0.2, 0.4, 0.6, 0.8, 1].map((t) => t * yMax);
  const xt = Array.from({ length: 6 }, (_, i) => x0 + ((x1 - x0) * i) / 5);
  // direct labels at the line ends, pushed apart so they never overlap (min 14px)
  const labels = series.filter((s) => s.points.length).map((s) => ({ name: s.name, x: X(s.points[s.points.length - 1].x),
    y: Y(s.points[s.points.length - 1].y) })).sort((a, b) => a.y - b.y);
  for (let i = 1; i < labels.length; i++) if (labels[i].y - labels[i - 1].y < 14) labels[i].y = labels[i - 1].y + 14;
  const at = (s, x) => { let v = null; for (const p of s.points) { if (p.x <= x) v = p.y; } return v; };
  return (
    <div style={{ position: "relative" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="line chart"
           onMouseMove={(e) => { const r = e.currentTarget.getBoundingClientRect(); const px = ((e.clientX - r.left) / r.width) * W;
             if (px >= L && px <= W - R) setHx(x0 + ((px - L) / (W - L - R)) * (x1 - x0)); }}
           onMouseLeave={() => setHx(null)}>
        {thresholds.map((t) => (
          <g key={t.y}>
            <line x1={L} x2={W - R} y1={Y(t.y)} y2={Y(t.y)} stroke="#a0aec0" strokeDasharray="4 4" />
            <text x={L + 6} y={Y(t.y) - 5} fontSize="11" fill="#718096">{t.label}</text>
          </g>
        ))}
        {ticks.map((t) => (
          <g key={t}><line x1={L} x2={W - R} y1={Y(t)} y2={Y(t)} stroke="#eef1f5" />
            <text x={L - 8} y={Y(t) + 4} fontSize="11" fill="#718096" textAnchor="end">{t.toFixed(1)}</text></g>
        ))}
        {xt.map((t, i) => <text key={i} x={X(t)} y={H - 12} fontSize="11" fill="#718096" textAnchor="middle">{t.toFixed(x1 - x0 < 3 ? 2 : 1)}</text>)}
        {xLabel && <text x={(L + W - R) / 2} y={H} fontSize="11" fill="#718096" textAnchor="middle">{xLabel}</text>}
        {series.map((s) => <path key={s.name} d={path(s.points)} fill="none" stroke={s.color} strokeWidth="2" />)}
        {labels.map((l) => <text key={l.name} x={l.x + 6} y={l.y + 4} fontSize="11.5" fill="#13233f">{l.name}</text>)}
        {hx !== null && <line x1={X(hx)} x2={X(hx)} y1={T} y2={H - B} stroke="#13233f" strokeOpacity="0.35" />}
      </svg>
      {hx !== null && (
        <div className="tip" style={{ left: `${(X(hx) / W) * 100}%`, top: 10, transform: "translate(-50%, 0)", whiteSpace: "normal" }}>
          <div>{xLabel} {hx.toFixed(2)}</div>
          {series.map((s) => { const v = at(s, hx); return v === null ? null : <div key={s.name}>{s.name}: {v.toFixed(3)}</div>; })}
        </div>
      )}
      <div className="legend">{series.map((s) => <span key={s.name}><i style={{ background: s.color }} />{s.name}</span>)}</div>
    </div>
  );
}
