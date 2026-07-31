"""EasyHunt AI — agentic VAPT orchestrator.

Five layers, kept strictly separate:

    L5  strategy   the Claude CLI agent (no network access of its own)
    L4  method     Claude Skills, one per VAPT phase
    L3  control    this package's MCP server — the security boundary
    L2  execution  engine tier (BBOT/Nuclei/Osmedeus) + atomic tool wrappers
    L1  knowledge  rule packs, task graph, findings store, evidence

Authorized testing only: owned assets, in-scope bug bounty programs, or org
assets with documented written approval.
"""

__version__ = "2.0.0"

from easyhunt.errors import (
    ApprovalRequired,
    BudgetExceeded,
    EasyHuntError,
    OutOfScopeError,
    SanitizeError,
    StaleScopeError,
)

__all__ = [
    "__version__",
    "ApprovalRequired",
    "BudgetExceeded",
    "EasyHuntError",
    "OutOfScopeError",
    "SanitizeError",
    "StaleScopeError",
]
