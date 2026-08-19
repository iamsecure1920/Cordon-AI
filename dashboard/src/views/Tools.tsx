import { useMemo, useState } from "react";
import type { DashboardState, ToolUsage } from "../types";
import { SearchInput, Select, EmptyState } from "../components/ui";

export function Tools({ state }: { state: DashboardState }) {
  const tools = state.tools ?? [];
  const [search, setSearch] = useState("");
  const [phase, setPhase] = useState("");

  const phases = useMemo(
    () => [...new Set(tools.flatMap((t) => t.phases))].sort(),
    [tools],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return tools.filter((t) => {
      if (q && !`${t.tool} ${t.phases.join(" ")}`.toLowerCase().includes(q)) return false;
      if (phase && !t.phases.includes(phase)) return false;
      return true;
    });
  }, [tools, search, phase]);

  const totalCalls = tools.reduce((a, t) => a + t.calls, 0);
  const totalFindings = tools.reduce((a, t) => a + t.findings, 0);
  const errorTools = tools.filter((t) => t.errors > 0).length;

  return (
    <div>
      <div className="grid-cards" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))" }}>
        <Stat k="Tools fired" v={tools.length} />
        <Stat k="Tool calls" v={totalCalls} />
        <Stat k="Findings from tools" v={totalFindings} cls="run" />
        <Stat k="Tools with errors" v={errorTools} cls={errorTools ? "crit" : "dim"} />
      </div>

      <div className="filterbar">
        <SearchInput value={search} onChange={setSearch} placeholder="search tool…" />
        <Select value={phase} onChange={setPhase} options={phases} allLabel="all phases" />
        <span style={{ marginLeft: "auto", color: "var(--faint)", fontSize: 12 }}>
          Every tool that fired in this engagement, from the audit trail
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState><b>No tools have fired yet.</b><br />Tools are recorded from the audit trail as phases run.</EmptyState>
      ) : (
        <div className="tbl-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Tool</th><th>Calls</th><th>Phases</th><th>Outcomes</th>
                <th>Findings</th><th>Errors</th><th>Last call</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t: ToolUsage) => (
                <tr key={t.tool}>
                  <td style={{ fontWeight: 600 }} className="mono">{t.tool}</td>
                  <td>{t.calls}</td>
                  <td>
                    {t.phases.map((p) => (
                      <span key={p} className="chip" style={{ cursor: "default", marginRight: 4, marginBottom: 2, fontSize: 11 }}>{p}</span>
                    ))}
                  </td>
                  <td>
                    {t.outcomes.map((o) => (
                      <span key={o} className={`chip o-${o}`} style={{ cursor: "default", marginRight: 4, marginBottom: 2, fontSize: 11, color: "var(--dim)" }}>{o}</span>
                    ))}
                  </td>
                  <td>{t.findings ? <span style={{ color: "var(--med)", fontWeight: 700 }}>{t.findings}</span> : "—"}</td>
                  <td>{t.errors ? <span style={{ color: "var(--fail)" }}>{t.errors}</span> : "—"}</td>
                  <td className="mono" style={{ color: "var(--faint)" }}>{(t.last_ts ?? "").slice(5, 19).replace("T", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Stat({ k, v, cls = "dim" }: { k: string; v: number; cls?: "crit" | "run" | "dim" }) {
  return (
    <div className="card">
      <div className="k">{k}</div>
      <div className={`v ${cls}`}>{v}</div>
    </div>
  );
}
