import { useMemo, useState } from "react";
import { FileText, Brain } from "lucide-react";
import type { DashboardState } from "../types";
import { SearchInput, EmptyState } from "../components/ui";

export function FalsePositives({ state }: { state: DashboardState }) {
  const fps = state.false_positives ?? [];
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return fps;
    return fps.filter((f) =>
      `${f.title} ${f.reason} ${f.source_tool ?? ""}`.toLowerCase().includes(q));
  }, [fps, search]);

  if (!fps.length) {
    return (
      <EmptyState>
        <b>No false positives on record.</b><br />
        When triage drops a finding or the brain learns an FP lesson, it is recorded here —
        nothing disappears silently.
      </EmptyState>
    );
  }

  return (
    <div>
      <div className="filterbar">
        <SearchInput value={search} onChange={setSearch} placeholder="search dismissed findings, lessons…" />
        <span style={{ marginLeft: "auto", color: "var(--faint)", fontSize: 12 }}>
          {filtered.length} of {fps.length} · dismissed findings + learned lessons
        </span>
      </div>
      <div className="feed">
        {filtered.map((f, i) => {
          const isLesson = f.kind === "brain-lesson";
          return (
            <div className="fe" key={i} style={{ alignItems: "flex-start", padding: "10px 14px" }}>
              <span style={{ marginTop: 2 }}>
                {isLesson ? <Brain size={15} color="var(--violet)" /> : <FileText size={15} color="var(--fail)" />}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                <div style={{ color: "var(--dim)", fontSize: 12.5, marginTop: 3 }}>{f.reason}</div>
                <div className="row" style={{ marginTop: 6, gap: 6 }}>
                  {f.source_tool ? <span className="chip" style={{ cursor: "default" }}>{f.source_tool}</span> : null}
                  {f.phase ? <span className="chip" style={{ cursor: "default" }}>phase: {f.phase}</span> : null}
                  {f.asset ? <span className="chip" style={{ cursor: "default" }}>{f.asset}</span> : null}
                  {f.count ? <span className="chip" style={{ cursor: "default" }}>×{f.count}</span> : null}
                  {f.context && Object.keys(f.context).length ? (
                    <span className="chip" style={{ cursor: "default" }}>
                      {Object.entries(f.context).map(([k, v]) => `${k}=${v}`).join(" · ")}
                    </span>
                  ) : null}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
