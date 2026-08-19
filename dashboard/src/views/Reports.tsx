import { FileText } from "lucide-react";
import type { DashboardState } from "../types";
import { EmptyState } from "../components/ui";

export function Reports({ state }: { state: DashboardState }) {
  const reports = state.reports ?? [];
  const workspaceName = state.workspace_name ?? "";

  if (!reports.length) {
    return (
      <EmptyState>
        <b>No reports generated yet.</b><br />
        Run the report phase (or <span className="mono">easyhunt report</span>) — PDFs and markdown land in the
        workspace and appear here.
      </EmptyState>
    );
  }

  return (
    <div>
      <div className="section-title">
        {reports.length} report{reports.length === 1 ? "" : "s"} in {workspaceName}
        <span className="rule" />
      </div>
      {reports.map((r) => {
        const name = r.split("/").pop() ?? r;
        const isPdf = r.endsWith(".pdf");
        return (
          <a key={r} className="report-link" href={`reports/${encodeURIComponent(name)}`} target="_blank" rel="noreferrer">
            <FileText size={16} color={isPdf ? "var(--fail)" : "var(--accent)"} />
            <span className="mono">{r}</span>
            <span style={{ marginLeft: "auto", color: "var(--faint)", fontSize: 11 }}>
              {isPdf ? "PDF" : "markdown"}
            </span>
          </a>
        );
      })}
    </div>
  );
}
