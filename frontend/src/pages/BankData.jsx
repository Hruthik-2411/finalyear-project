import { useState } from "react";
import { useData } from "../ui.jsx";

const TABS = [["accounts", "Accounts"], ["customers", "Customers"], ["transactions", "Transactions"], ["loans", "Loans"],
  ["fraud_cases", "Fraud cases"], ["case_notes", "Case notes"], ["policies", "Policy center"]];

export default function BankData({ initial = "accounts" }) {
  const [tab, setTab] = useState(initial);
  const [q, setQ] = useState("");
  const [rows] = useData(`/api/data/${tab}?q=${encodeURIComponent(q)}&limit=300`, [tab, q], 4000);
  const cols = rows && rows.length ? Object.keys(rows[0]) : [];
  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Bank data</h1><p>The synthetic FinSecure dataset the agents work on. It refreshes every few seconds, so you can watch an attack change it.</p></div>
        <input className="search" placeholder="Search, e.g. ACC-1012" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="tabs">{TABS.map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}</div>
      <div className="panel" style={{ padding: 0 }}>
        <div className="scroll" style={{ border: 0, maxHeight: 680 }}>
          {!rows ? <div className="empty">Loading...</div> : !rows.length ? <div className="empty">No rows match.</div> : (
            <table className="t">
              <thead><tr>{cols.map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}</tr></thead>
              <tbody>{rows.map((r, i) => (
                <tr key={i}>{cols.map((c) => (
                  <td key={c} className={String(r[c]).length > 60 ? "small" : ""}
                      style={(c === "status" && ["FROZEN", "ESCALATED", "REJECTED", "SUSPENDED"].includes(r[c])) || r[c] === "ACC-9999" ? { color: "var(--block)", fontWeight: 600 } : {}}>
                    {typeof r[c] === "number" && c.match(/balance|amount/) ? r[c].toLocaleString("en-IN") : String(r[c])}
                  </td>))}</tr>))}</tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
