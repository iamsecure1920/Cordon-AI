import { useMemo, useState } from "react";
import type { DashboardState, CoverageRow } from "../types";
import { Badge, ChipGroup, EmptyState } from "../components/ui";

export function Coverage({ state }: { state: DashboardState }) {
  const rows = state.coverage?.rows ?? [];
  const byStatus = state.coverage?.by_status ?? {};
  const [status, setStatus] = useState<string[]>([]);
  const [search, setSearch] = useState("");

  const statuses = useMemo(
    () => [...new Set(rows.map((r) => r.status).filter(Boolean))].sort(),
    [rows],
  );

  const toggle = (v: string) =>
    setStatus(status.includes(v) ? status.filter((x) => x !== v) : [...status, v]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows.filter((r) => {
      if (status.length && !status.includes(r.status)) return false;
      if (q && !`${r.class} ${r.tool} ${r.note ?? ""}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [rows, status, search]);

  const total = rows.length;
  const validated = byStatus.validated ?? 0;

  return (
    <div>
      <div className="grid-cards" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))" }}>
        <Stat k="Classes tracked" v={total} />
        <Stat k="Validated" v={validated} cls="ok" />
        <Stat k="Detected" v={byStatus.detected ?? 0} cls="run" />
        <Stat k="Not attempted" v={byStatus.not_attempted ?? 0} cls="dim" />
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="dk" style={{ color: "var(--faint)", fontSize: 10, textTransform: "uppercase", letterSpacing: ".1em" }}>Pipeline completion</div>
        <div className="bar" style={{ marginTop: 8 }}>
          <div style={{ width: `${total ? Math.round((validated / total) * 100) : 0}%`, background: "var(--ok)" }} />
        </div>
        <div style={{ color: "var(--dim)", fontSize: 12, marginTop: 6 }}>
          {validated}/{total} bug classes confirmed end-to-end this run
        </div>
      </div>

      <div className="filterbar">
        <input type="text" placeholder="search class, tool…" value={search} onChange={(e) => setSearch(e.target.value)} />
        <ChipGroup label="Status" options={statuses} selected={status} onToggle={toggle} counts={byStatus} />
      </div>

      {filtered.length === 0 ? (
        <EmptyState><b>No coverage rows.</b><br />The CoverageLedger is written as phases run — run scan/exploit phases to populate it.</EmptyState>
      ) : (
        <div className="tbl-wrap">
          <table className="data">
            <thead>
              <tr><th>Bug class</th><th>Runtime status</th><th>Tool</th><th>Note</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {filtered.map((r: CoverageRow) => (
                <tr key={r.class}>
                  <td style={{ fontWeight: 600 }}>{r.class}</td>
                  <td><Badge kind="st" value={r.status} /></td>
                  <td className="mono">{r.tool ?? "—"}</td>
                  <td style={{ color: "var(--dim)" }}>{r.note ?? ""}</td>
                  <td className="mono" style={{ color: "var(--faint)" }}>{(r.last_seen ?? "").slice(0, 19).replace("T", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Stat({ k, v, cls = "dim" }: { k: string; v: number; cls?: "ok" | "run" | "dim" }) {
  return (
    <div className="card">
      <div className="k">{k}</div>
      <div className={`v ${cls}`}>{v}</div>
    </div>
  );
}
