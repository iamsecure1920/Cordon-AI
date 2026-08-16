"""The planner, and the one distinction it must not lose.

`hunt_plan` turns recon output into things worth trying. Once `auth_crawl`
exists, the single most important fact about a URL is whether it was visible
only to a logged-in user — that is the surface every scanner in this toolchain
has been blind to, and where the categories that pay actually live. Averaging it
into a list of 2,700 anonymous URLs throws that fact away.

The bug these tests exist for: the emptiness check summed the top-level lists,
the authenticated surface is a nested dict, and a run holding three
authenticated URLs and twenty-three object-reference candidates reported "the
asset store is empty, so there is nothing to reason about". The most valuable
input this tool has ever been handed, discarded by a check that could not see it.
"""

from __future__ import annotations

import pytest

from easyhunt.knowledge.findings import Asset
from easyhunt.knowledge.sessions import Session
from easyhunt.tools.hunt_plan import hunt_plan

pytestmark = pytest.mark.asyncio

HOST = "www.example.com"


def anonymous(engagement, *urls: str) -> None:
    engagement.assets.add_many(
        Asset(value=u, kind="url", source="http_probe", host=HOST, tags=["live"])
        for u in urls
    )


def behind_login(engagement, *urls: str) -> None:
    engagement.assets.add_many(
        Asset(value=u, kind="url", source="auth_crawl", host=HOST,
              tags=["live", "authenticated"])
        for u in urls
    )


def never_fetched(engagement, *urls: str) -> None:
    engagement.assets.add_many(
        Asset(value=u, kind="object_reference", source="auth_crawl", host=HOST,
              tags=["authenticated", "not-fetched"])
        for u in urls
    )


def identity(engagement, name: str, role: str) -> None:
    engagement.sessions.add(Session(name=name, role=role, host=HOST, cookies={"sid": "x"}))


class TestEmptiness:
    async def test_an_empty_store_says_so(self, engagement) -> None:
        result = await hunt_plan()
        assert result["ok"] is False
        assert result["error"] == "no_surface"

    async def test_an_authenticated_only_surface_is_not_empty(self, engagement) -> None:
        # The bug. Every URL is tagged `authenticated`, so the anonymous list is
        # empty and every other top-level list is empty — and the surface that
        # matters most is sitting in a nested dict.
        behind_login(engagement, f"https://{HOST}/orders/1042")
        never_fetched(engagement, f"https://{HOST}/api/users/7")
        result = await hunt_plan()
        assert result["ok"] is True
        assert result["actionable"] > 0

    async def test_candidates_alone_are_enough_to_reason_about(self, engagement) -> None:
        never_fetched(engagement, f"https://{HOST}/api/users/7")
        result = await hunt_plan()
        assert result["ok"] is True


class TestTheSurfaceStaysSeparated:
    async def test_authenticated_urls_are_not_mixed_into_the_public_list(
        self, engagement
    ) -> None:
        anonymous(engagement, f"https://{HOST}/pricing")
        behind_login(engagement, f"https://{HOST}/orders/1042")
        surface = (await hunt_plan())["surface"]

        assert surface["live_urls"] == [f"https://{HOST}/pricing"]
        assert surface["authenticated"]["urls"] == [f"https://{HOST}/orders/1042"]

    async def test_unfetched_candidates_are_reported(self, engagement) -> None:
        behind_login(engagement, f"https://{HOST}/me")
        never_fetched(engagement, f"https://{HOST}/api/users/7", f"https://{HOST}/api/users/8")
        surface = (await hunt_plan())["surface"]
        # The application named these and auth_crawl deliberately did not read
        # them. Sharpest access-control leads in the whole surface.
        assert len(surface["authenticated"]["reference_candidates_unfetched"]) == 2

    async def test_no_session_means_no_authenticated_section(self, engagement) -> None:
        anonymous(engagement, f"https://{HOST}/pricing")
        assert "authenticated" not in (await hunt_plan())["surface"]

    async def test_the_agent_is_told_to_start_with_the_login_surface(
        self, engagement
    ) -> None:
        anonymous(engagement, f"https://{HOST}/pricing")
        behind_login(engagement, f"https://{HOST}/orders/1042")
        result = await hunt_plan()
        assert result["instructions"].startswith("Start with `authenticated`")

    async def test_without_a_session_the_generic_guidance_is_used(
        self, engagement
    ) -> None:
        anonymous(engagement, f"https://{HOST}/doc?id=5")
        assert "worth_a_look" in (await hunt_plan())["instructions"]

    async def test_junk_endpoints_do_not_crash_the_planner(self, engagement) -> None:
        # js_analyze scrapes whatever looks link-like out of bundles, and that
        # is not always a URL: an XPath selector like //*[@id='...'] reads to
        # urlsplit as a malformed IPv6 literal and raises ValueError. One junk
        # endpoint took the whole planning phase down on ATT; it must be
        # skipped, not fatal.
        anonymous(engagement, f"https://{HOST}/pricing")
        engagement.assets.add_many(
            [Asset(value="//*[@id='widget']", kind="endpoint", source="js_analyze", host=HOST)]
        )
        result = await hunt_plan()
        assert result["ok"] is True
        assert "worth_a_look" in result["instructions"]


class TestGapsTrackWhatWasActuallyDone:
    async def test_no_session_asks_for_one(self, engagement) -> None:
        anonymous(engagement, f"https://{HOST}/pricing")
        gaps = " ".join((await hunt_plan())["gaps"])
        assert "Nothing authenticated" in gaps
        assert "auth_surface" in gaps

    async def test_one_identity_asks_for_a_second(self, engagement) -> None:
        behind_login(engagement, f"https://{HOST}/orders/1042")
        identity(engagement, "alice", "user-a")
        gaps = " ".join((await hunt_plan())["gaps"])
        # Telling an operator to capture a session they already captured is the
        # advice being wrong, not the target being thin.
        assert "Nothing authenticated" not in gaps
        assert "second of different privilege" in gaps

    async def test_two_identities_with_references_asks_for_neither(
        self, engagement
    ) -> None:
        behind_login(engagement, f"https://{HOST}/orders/1042")
        never_fetched(engagement, f"https://{HOST}/api/users/7")
        identity(engagement, "alice", "user-a")
        identity(engagement, "bob", "user-b")
        gaps = " ".join((await hunt_plan())["gaps"])
        assert "second of different privilege" not in gaps
        assert "Nothing authenticated" not in gaps

    async def test_two_identities_without_references_says_what_is_missing(
        self, engagement
    ) -> None:
        behind_login(engagement, f"https://{HOST}/dashboard")
        identity(engagement, "alice", "user-a")
        identity(engagement, "bob", "user-b")
        gaps = " ".join((await hunt_plan())["gaps"])
        # Two accounts and nothing to aim them at is a real, distinct gap.
        assert "no object references found behind the login" in gaps
