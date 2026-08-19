import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { DashboardState, Finding, Severity, Status } from "../types";
import { Badge, SearchInput, Select, ChipGroup, EmptyState } from "../components/ui";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: Status[] = ["confirmed", "candidate", "needs_manual_review", "untested", "false_positive", "dismissed"];

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function Findings({ state }: { state: DashboardState }) {
  const all = state.findings.findings ?? [];
  const [search, setSearch] = useState("");
  const [sev, setSev] = useState<Severity[]>([]);
  const [status, setStatus] = useState<Status[]>([]);
  const [phase, setPhase] = useState("");
  const [tool, setTool] = useState("");
  const [sort, setSort] = useState("severity");
  const [expanded, setExpanded] = useState<Set<string | null>>(new Set());

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of all) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [all]);
  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of all) c[f.status] = (c[f.status] ?? 0) + 1;
    return c;
  }, [all]);
  const phases = useMemo(() => [...new Set(all.map((f) => f.phase).filter(Boolean))].sort(), [all]);
  const tools = useMemo(() => [...new Set(all.map((f) => f.source_tool).filter(Boolean))].sort(), [all]);

  const toggle = <T,>(list: T[], v: T, set: (x: T[]) => void) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let out = all.filter((f) => {
      if (q) {
        const hay = `${f.title} ${f.asset} ${f.source_tool} ${f.phase} ${f.id ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (sev.length && !sev.includes(f.severity)) return false;
      if (status.length && !status.includes(f.status)) return false;
      if (phase && f.phase !== phase) return false;
      if (tool && f.source_tool !== tool) return false;
      return true;
    });
    switch (sort) {
      case "severity":
        out = [...out].sort((a, b) =>
          SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
          (b.confidence ?? 0) - (a.confidence ?? 0));
        break;
      case "cvss":
        out = [...out].sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1));
        break;
      case "asset":
        out = [...out].sort((a, b) => String(a.asset).localeCompare(String(b.asset)));
        break;
      case "newest":
        out = [...out].sort((a, b) => String(b.first_seen ?? "").localeCompare(String(a.first_seen ?? "")));
        break;
    }
    return out;
  }, [all, search, sev, status, phase, tool, sort]);

  const active = search !== "" || sev.length > 0 || status.length > 0 || phase !== "" || tool !== "";
  const reset = () => { setSearch(""); setSev([]); setStatus([]); setPhase(""); setTool(""); };

  const toggleRow = (id: string | null) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });

  return (
    <div>
      <div className="filterbar">
        <SearchInput value={search} onChange={setSearch} placeholder="search title, asset, tool, id…" />
        <ChipGroup label="Severity" options={SEVS} selected={sev} onToggle={(v) => toggle(sev, v, setSev)} counts={sevCounts} />
        <ChipGroup label="Status" options={STATUSES} selected={status} onToggle={(v) => toggle(status, v, setStatus)} counts={statusCounts} />
        <Select value={phase} onChange={setPhase} options={phases} allLabel="all phases" />
        <Select value={tool} onChange={setTool} options={tools} allLabel="all tools" />
        <Select value={sort} onChange={setSort} options={["severity", "cvss", "asset", "newest"]} allLabel="sort" />
        {active ? (
          <button className="chip" onClick={reset} style={{ marginLeft: "auto" }}>
            clear filters
          </button>
        ) : null}
      </div>

      {filtered.length === 0 ? (
        <EmptyState>
          <b>{all.length ? "No findings match the current filters." : "No findings on the ledger yet."}</b>
          <br />{all.length ? "Try clearing filters, or run more phases." : "Run a scan — candidates land here as they're filed."}
        </EmptyState>
      ) : (
        <div className="tbl-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 30 }} />
                <th>Severity</th>
                <th>Finding</th>
                <th>Asset</th>
                <th>Status</th>
                <th>Phase</th>
                <th>Tool</th>
                <th>CVSS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => {
                const isOpen = expanded.has(f.id);
                const isFp = f.status === "false_positive" || f.status === "dismissed";
                return (
                  <RowGroup key={f.id ?? f.title} finding={f} open={isOpen}
                    onToggle={() => toggleRow(f.id)} dim={isFp} />
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div style={{ marginTop: 10, color: "var(--faint)", fontSize: 12 }}>
        {filtered.length} of {all.length} findings shown
      </div>
    </div>
  );
}

function RowGroup({ finding: f, open, onToggle, dim }: {
  finding: Finding; open: boolean; onToggle: () => void; dim: boolean;
}) {
  return (
    <>
      <tr style={dim ? { opacity: 0.62, cursor: "pointer" } : { cursor: "pointer" }} onClick={onToggle}>
        <td>{open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</td>
        <td><Badge kind="sev" value={f.severity} /></td>
        <td style={{ fontWeight: 600 }}>{f.title}</td>
        <td className="mono" style={{ maxWidth: 240, wordBreak: "break-all" }}>{f.asset}</td>
        <td><Badge kind="st" value={f.status} /></td>
        <td>{f.phase}</td>
        <td className="mono">{f.source_tool ?? ""}</td>
        <td>{f.cvss != null ? f.cvss.toFixed(1) : "—"}</td>
      </tr>
      {open ? (
        <tr className="detail-row">
          <td />
          <td colSpan={7}>
            <Detail finding={f} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function Detail({ finding: f }: { finding: Finding }) {
  const ev = (f.evidence ?? []) as unknown[];
  const desc = f.description;
  const refs = f.references ?? [];
  return (
    <div className="detail-grid">
      {desc ? (
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="dk">Description</div>
          <div className="dv">{desc}</div>
        </div>
      ) : null}
      {f.cvss_vector ? (
        <div>
          <div className="dk">CVSS vector</div>
          <div className="dv mono">{f.cvss_vector}</div>
        </div>
      ) : null}
      {f.rule_id ? (
        <div>
          <div className="dk">Rule</div>
          <div className="dv mono">{f.rule_id}</div>
        </div>
      ) : null}
      {f.first_seen ? (
        <div>
          <div className="dk">First seen</div>
          <div className="dv mono">{f.first_seen}</div>
        </div>
      ) : null}
      {f.validated != null ? (
        <div>
          <div className="dk">Validated</div>
          <div className="dv">{String(f.validated)}</div>
        </div>
      ) : null}
      {f.is_canary ? (
        <div>
          <div className="dk">Canary</div>
          <div className="dv">yes — control finding</div>
        </div>
      ) : null}
      {(f.tags ?? []).length ? (
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="dk">Tags</div>
          <div className="row">
            {(f.tags ?? []).map((t) => <span key={t} className="chip on" style={{ cursor: "default" }}>{t}</span>)}
          </div>
        </div>
      ) : null}
      {ev.length ? (
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="dk">Evidence</div>
          {ev.slice(0, 5).map((e, i) => (
            <div key={i} className="evidence" style={{ marginBottom: 6 }}>
              {typeof e === "string" ? e : JSON.stringify(e, null, 1)}
            </div>
          ))}
        </div>
      ) : null}
      {f.remediation ? (
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="dk">Remediation</div>
          <div className="dv">{f.remediation}</div>
        </div>
      ) : null}
      {refs.length ? (
        <div style={{ gridColumn: "1 / -1" }}>
          <div className="dk">References</div>
          <div className="dv">{refs.map((r, i) => <div key={i}><a href={r} target="_blank" rel="noreferrer">{r}</a></div>)}</div>
        </div>
      ) : null}
    </div>
  );
}
