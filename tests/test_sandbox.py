"""Sandbox: image resolution, path translation, network isolation, and the one
behaviour that matters most — a host fallback must never be silent.

The unit tests below run everywhere. The container tests at the bottom skip
unless a Docker daemon and ``cordon:latest`` are actually present, because
"the plan says sandboxed: true" is not evidence that anything ran in a container.
Where the image exists they execute a real binary inside it and check the output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cordon.control_plane.sandbox import CONTAINER_WORKDIR, Sandbox, SandboxConfig
from cordon.errors import ToolUnavailable

SHARED_IMAGE = "cordon:latest"


def _docker_ok() -> bool:
    binary = shutil.which("docker")
    if not binary:
        return False
    try:
        return (
            subprocess.run(  # noqa: S603
                [binary, "image", "inspect", SHARED_IMAGE],
                capture_output=True,
                timeout=20,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_image = pytest.mark.skipif(
    not _docker_ok(), reason=f"needs a Docker daemon and the {SHARED_IMAGE} image"
)


def make_sandbox(tmp_path: Path, **overrides) -> Sandbox:
    """A sandbox whose runtime/image probes are stubbed unless told otherwise."""
    data = {
        "mode": "docker",
        "default_image": SHARED_IMAGE,
        "verify_image_binary": False,
        "images": {"nuclei": "projectdiscovery/nuclei:latest"},
        **overrides,
    }
    sandbox = Sandbox(SandboxConfig.from_dict(data), workspace=tmp_path / "ws")
    sandbox.runtime_available = lambda: True  # type: ignore[method-assign]
    sandbox.image_present = lambda image: True  # type: ignore[method-assign]
    return sandbox


class TestImageResolution:
    def test_unmapped_tool_uses_the_default_image(self, tmp_path: Path) -> None:
        """The whole point: a tool with no `images:` entry is still sandboxed."""
        sandbox = make_sandbox(tmp_path)
        plan = sandbox.plan(tool="sqlmap", binary="sqlmap", argv=["-u", "https://x.test"])

        assert plan.sandboxed is True
        assert plan.image == SHARED_IMAGE
        assert plan.fallback_reason == ""

    def test_shared_image_receives_the_binary_name(self, tmp_path: Path) -> None:
        """The shared image's entrypoint execs its arguments; without the binary
        name it has nothing to run."""
        sandbox = make_sandbox(tmp_path)
        plan = sandbox.plan(tool="sqlmap", binary="sqlmap", argv=["--batch"])

        after_image = plan.argv[plan.argv.index(SHARED_IMAGE) + 1 :]
        assert after_image == ["sqlmap", "--batch"]

    def test_per_tool_image_still_wins_and_gets_no_binary_name(self, tmp_path: Path) -> None:
        """Existing mappings must keep working: their ENTRYPOINT *is* the tool,
        so prepending the name would make nuclei try to scan "nuclei"."""
        sandbox = make_sandbox(tmp_path)
        plan = sandbox.plan(tool="nuclei", binary="nuclei", argv=["-l", "hosts.txt"])

        assert plan.image == "projectdiscovery/nuclei:latest"
        after_image = plan.argv[plan.argv.index(plan.image) + 1 :]
        assert after_image == ["-l", "hosts.txt"]

    def test_explicit_mapping_to_the_shared_image_is_treated_as_shared(
        self, tmp_path: Path
    ) -> None:
        sandbox = make_sandbox(tmp_path, images={"sqlmap": SHARED_IMAGE})
        plan = sandbox.plan(tool="sqlmap", binary="sqlmap", argv=["--batch"])

        assert plan.argv[plan.argv.index(SHARED_IMAGE) + 1] == "sqlmap"

    def test_empty_default_image_restores_mapped_tools_only(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, default_image="")
        plan = sandbox.plan(tool="sqlmap", binary="sh", argv=["-c", "true"])

        assert plan.sandboxed is False
        assert "no image is mapped" in plan.fallback_reason

    def test_missing_binary_in_the_shared_image_falls_back(self, tmp_path: Path) -> None:
        """A build that logged `!!! FAILED: aderyn` still produces an image. The
        tool is absent from it, and that has to read as a fallback rather than a
        container that exits 127."""
        sandbox = make_sandbox(tmp_path, verify_image_binary=True)
        sandbox.binary_in_image = lambda image, binary: False  # type: ignore[method-assign]

        plan = sandbox.plan(tool="aderyn", binary="sh", argv=["-c", "true"])

        assert plan.sandboxed is False
        assert "not executable inside" in plan.fallback_reason

    def test_present_binary_in_the_shared_image_is_sandboxed(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, verify_image_binary=True)
        sandbox.binary_in_image = lambda image, binary: True  # type: ignore[method-assign]

        assert sandbox.plan(tool="aderyn", binary="aderyn", argv=[]).sandboxed is True


class TestNetworkIsolation:
    def test_configured_tool_gets_no_network(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, networks={"slither": "none"})
        plan = sandbox.plan(tool="slither", binary="slither", argv=["."])

        assert plan.network == "none"
        assert plan.argv[plan.argv.index("--network") + 1] == "none"

    def test_unconfigured_tool_keeps_the_default(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, networks={"slither": "none"})
        plan = sandbox.plan(tool="httpx", binary="httpx", argv=["-u", "https://x.test"])

        assert plan.network == "bridge"

    def test_caller_request_overrides_config(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, networks={"slither": "none"})
        plan = sandbox.plan(tool="slither", binary="slither", argv=["."], network="host")

        assert plan.network == "host"

    def test_host_fallback_admits_isolation_is_not_enforced(self, tmp_path: Path) -> None:
        """A tool configured `network: none` that ends up on the host has the
        host's entire network stack. Saying so is the whole job of this note."""
        sandbox = make_sandbox(tmp_path, networks={"slither": "none"}, default_image="")
        plan = sandbox.plan(tool="slither", binary="sh", argv=["-c", "true"])

        assert plan.network == "host"
        assert "NOT enforced on the host" in plan.note

    def test_capability_allowlist_is_still_closed(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)
        with pytest.raises(ToolUnavailable, match="disallowed capabilities"):
            sandbox.plan(tool="nmap", binary="nmap", argv=["-sS"], capabilities=["SYS_ADMIN"])

    def test_allowed_capability_reaches_the_command(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)
        plan = sandbox.plan(tool="nmap", binary="nmap", argv=["-sS"], capabilities=["net_raw"])

        assert "--cap-add" in plan.argv
        assert plan.argv[plan.argv.index("--cap-add") + 1] == "NET_RAW"


class TestPathTranslation:
    """Workspace paths that survive untranslated produce empty output files in a
    directory nobody reads — a scan that looks clean because it wrote elsewhere."""

    def translate(self, sandbox: Sandbox, token: str) -> str:
        return sandbox._translate_paths([token])[0]

    def test_workspace_root_and_children(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)
        root = str(sandbox.workspace)

        assert self.translate(sandbox, root) == CONTAINER_WORKDIR
        assert self.translate(sandbox, f"{root}/raw/out.json") == f"{CONTAINER_WORKDIR}/raw/out.json"

    def test_sibling_directory_is_not_rewritten(self, tmp_path: Path) -> None:
        """A workspace at /engagements/acme must not capture /engagements/acme-old."""
        sandbox = make_sandbox(tmp_path)
        sibling = str(sandbox.workspace) + "-old/leak.json"

        assert self.translate(sandbox, sibling) == sibling

    def test_flag_equals_path(self, tmp_path: Path) -> None:
        """semgrep --output=PATH, wapiti --output=PATH: one token, two halves."""
        sandbox = make_sandbox(tmp_path)
        token = f"--output={sandbox.workspace}/raw/o.json"

        assert self.translate(sandbox, token) == f"--output={CONTAINER_WORKDIR}/raw/o.json"

    def test_comma_joined_paths_translate_every_element(self, tmp_path: Path) -> None:
        """nuclei -t a,b. Rewriting only the first element leaves the rest
        pointing at host paths the container cannot see."""
        sandbox = make_sandbox(tmp_path)
        root = sandbox.workspace
        token = f"{root}/a.yaml,{root}/b.yaml"

        assert self.translate(sandbox, token) == f"{CONTAINER_WORKDIR}/a.yaml,{CONTAINER_WORKDIR}/b.yaml"

    def test_ordinary_comma_lists_are_untouched(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)

        assert self.translate(sandbox, "200,301,403") == "200,301,403"
        assert self.translate(sandbox, "low,medium,high") == "low,medium,high"

    def test_paths_outside_the_workspace_are_never_invented(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)

        assert self.translate(sandbox, "/etc/passwd") == "/etc/passwd"
        assert self.translate(sandbox, "-silent") == "-silent"

    def test_symlinked_workspace_still_translates(self, tmp_path: Path) -> None:
        """Engagement keeps the path it was given; Sandbox resolves it. On a host
        where the workspace root traverses a symlink the two differ, and only the
        unresolved spelling ever appears in a wrapper's argv."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)

        sandbox = Sandbox(
            SandboxConfig.from_dict({"mode": "docker", "default_image": SHARED_IMAGE}),
            workspace=link,
        )
        assert self.translate(sandbox, f"{link}/raw/o.json") == f"{CONTAINER_WORKDIR}/raw/o.json"
        assert self.translate(sandbox, f"{real}/raw/o.json") == f"{CONTAINER_WORKDIR}/raw/o.json"

    def test_staged_payload_and_wordlist_paths_translate(self, tmp_path: Path) -> None:
        """content_discovery and _stage_payload_list both copy the vetted store
        into the workspace precisely so the sandbox can see them. Verify the copy
        lands on the writable mount."""
        sandbox = make_sandbox(tmp_path)
        staged = sandbox.workspace / "raw" / "payloads-xss-basic.txt"
        wordlist = sandbox.workspace / "raw" / "wordlist-juicy-paths.txt"

        plan = sandbox.plan(
            tool="ffuf",
            binary="ffuf",
            argv=["-w", str(wordlist), "-o", str(sandbox.workspace / "raw" / "ffuf.json")],
        )
        assert f"{CONTAINER_WORKDIR}/raw/wordlist-juicy-paths.txt" in plan.argv
        assert f"{CONTAINER_WORKDIR}/raw/ffuf.json" in plan.argv
        assert self.translate(sandbox, str(staged)) == f"{CONTAINER_WORKDIR}/raw/payloads-xss-basic.txt"

    def test_the_workspace_is_the_only_writable_mount(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path)
        plan = sandbox.plan(tool="sqlmap", binary="sqlmap", argv=["--batch"])

        writable = [a for a in plan.argv if a.endswith(":rw")]
        assert writable == [f"{sandbox.workspace}:{CONTAINER_WORKDIR}:rw"]


class TestMountsAndScratch:
    def test_configured_mount_is_added(self, tmp_path: Path) -> None:
        host = tmp_path / "solc-select"
        host.mkdir()
        sandbox = make_sandbox(
            tmp_path, mounts={"slither": [f"{host}:/root/.solc-select:ro"]}
        )
        plan = sandbox.plan(tool="slither", binary="slither", argv=["."])

        assert f"{host}:/root/.solc-select:ro" in plan.argv

    def test_absent_host_path_is_skipped_not_mounted(self, tmp_path: Path) -> None:
        """Docker would create an empty directory. An empty compiler cache or an
        empty template library looks configured and behaves as if it were not."""
        missing = tmp_path / "nope"
        sandbox = make_sandbox(tmp_path, mounts={"slither": [f"{missing}:/root/x:ro"]})
        plan = sandbox.plan(tool="slither", binary="slither", argv=["."])

        assert not any("/root/x" in a for a in plan.argv)

    def test_tmpfs_scratch_is_added(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, tmpfs={"sqlmap": ["/root/.local/share/sqlmap"]})
        plan = sandbox.plan(tool="sqlmap", binary="sqlmap", argv=["--batch"])

        assert any(a.startswith("/root/.local/share/sqlmap:rw") for a in plan.argv)

    def test_tmpfs_yields_to_a_bind_mount_on_the_same_path(self, tmp_path: Path) -> None:
        """Docker refuses to layer both, and the bind is the one carrying data."""
        host = tmp_path / "solc-select"
        host.mkdir()
        sandbox = make_sandbox(
            tmp_path,
            mounts={"slither": [f"{host}:/root/.solc-select:ro"]},
            tmpfs={"slither": ["/root/.solc-select"]},
        )
        plan = sandbox.plan(tool="slither", binary="slither", argv=["."])

        assert not any(a.startswith("/root/.solc-select:rw") for a in plan.argv)
        assert f"{host}:/root/.solc-select:ro" in plan.argv


class TestFallbackIsVisible:
    """The defect this module exists to prevent is a mapping that silently
    degrades to host execution. Four independent channels must show it."""

    def test_plan_carries_the_reason(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, default_image="")
        plan = sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        assert plan.fell_back is True
        assert plan.fallback_reason
        assert plan.describe()["fell_back"] is True
        assert "NOT SANDBOXED" in plan.note

    def test_sandbox_accumulates_a_report(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, default_image="")
        sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])
        sandbox.plan(tool="dnsreaper", binary="sh", argv=["-c", "true"])

        tools = [row["tool"] for row in sandbox.fallback_report()]
        assert tools == ["dnsreaper", "subzy"]
        assert sandbox.describe()["host_fallbacks"] == sandbox.fallback_report()

    def test_fallback_is_logged_at_warning(self, tmp_path: Path, caplog) -> None:
        sandbox = make_sandbox(tmp_path, default_image="")
        with caplog.at_level("WARNING", logger="cordon.sandbox"):
            sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        assert "SANDBOX FALLBACK" in caplog.text
        assert "subzy" in caplog.text

    def test_fallback_reaches_the_engagement_audit_log(self, engagement) -> None:
        """`audit_tail` is how an operator asks what actually happened. A silent
        fallback would be invisible there."""
        engagement.sandbox.config.mode = "docker"
        engagement.sandbox.config.default_image = ""
        engagement.sandbox.runtime_available = lambda: True  # type: ignore[method-assign]

        engagement.sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        events = [
            json.loads(line)
            for line in Path(engagement.audit.path).read_text(encoding="utf-8").splitlines()
        ]
        fallbacks = [e for e in events if e["event"] == "sandbox_fallback"]
        assert len(fallbacks) == 1
        assert fallbacks[0]["tool"] == "subzy"
        assert fallbacks[0]["reason"]

    def test_repeated_fallbacks_are_not_re_audited(self, engagement) -> None:
        engagement.sandbox.config.mode = "docker"
        engagement.sandbox.config.default_image = ""
        engagement.sandbox.runtime_available = lambda: True  # type: ignore[method-assign]

        for _ in range(3):
            engagement.sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        events = [
            json.loads(line)
            for line in Path(engagement.audit.path).read_text(encoding="utf-8").splitlines()
        ]
        assert sum(1 for e in events if e["event"] == "sandbox_fallback") == 1

    def test_mode_none_is_a_choice_not_a_degradation(self, tmp_path: Path) -> None:
        """`mode: none` inside an already-isolated VM is correct. Reporting it as
        a fallback would train operators to ignore the ones that matter."""
        sandbox = Sandbox(SandboxConfig.from_dict({"mode": "none"}), workspace=tmp_path / "ws")
        plan = sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        assert plan.sandboxed is False
        assert plan.fell_back is False
        assert sandbox.fallback_report() == []

    def test_fallback_disabled_raises_with_the_reason(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, default_image="", fallback_to_host=False)
        with pytest.raises(ToolUnavailable) as exc:
            sandbox.plan(tool="subzy", binary="sh", argv=["-c", "true"])

        assert "no image is mapped" in str(exc.value)

    def test_absent_everywhere_still_raises(self, tmp_path: Path) -> None:
        sandbox = make_sandbox(tmp_path, default_image="")
        with pytest.raises(ToolUnavailable, match="neither a sandbox image nor the host binary"):
            sandbox.plan(tool="ghost", binary="definitely-not-a-real-binary", argv=[])


@needs_image
class TestActuallyRunsInTheContainer:
    """`plan.sandboxed is True` proves nothing about where the process ran.
    These execute a binary inside the image and check what came back."""

    def real(self, tmp_path: Path, **overrides) -> Sandbox:
        data = {
            "mode": "docker",
            "default_image": SHARED_IMAGE,
            "verify_image_binary": True,
            "images": {},
            **overrides,
        }
        return Sandbox(SandboxConfig.from_dict(data), workspace=tmp_path / "ws")

    def run(self, plan) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            plan.argv, capture_output=True, text=True, timeout=300, check=False,
            cwd=str(plan.cwd),
        )

    def test_the_process_runs_inside_the_image_not_on_the_host(self, tmp_path: Path) -> None:
        """/etc/cordon-image-marker does not exist on the host. Reading the
        container's own filesystem is the difference between "planned" and "ran"."""
        sandbox = self.real(tmp_path)
        plan = sandbox.plan(
            tool="probe", binary="cat", argv=["/etc/hostname"], network="none"
        )
        assert plan.sandboxed is True

        proc = self.run(plan)
        assert proc.returncode == 0, proc.stderr
        # A container's hostname is its own 12-hex-digit id, never the host's.
        assert proc.stdout.strip() != Path("/etc/hostname").read_text(encoding="utf-8").strip()

    def test_binary_probe_agrees_with_the_image(self, tmp_path: Path) -> None:
        sandbox = self.real(tmp_path)

        assert sandbox.binary_in_image(SHARED_IMAGE, "slither") is True
        assert sandbox.binary_in_image(SHARED_IMAGE, "no-such-tool-xyz") is False

    def test_slither_analyses_a_workspace_contract_with_no_network(
        self, tmp_path: Path
    ) -> None:
        """The full shape: shared image, binary prepended, workspace path
        translated, network denied, real findings out the other end."""
        solc_select = Path("~/.solc-select").expanduser()
        if not solc_select.is_dir():
            pytest.skip("host has no populated ~/.solc-select to mount")

        sandbox = self.real(
            tmp_path,
            networks={"slither": "none"},
            mounts={"slither": [f"{solc_select}:/root/.solc-select:ro"]},
        )
        project = sandbox.workspace / "contracts"
        project.mkdir(parents=True, exist_ok=True)
        (project / "Vuln.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract Vuln {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function deposit() public payable { balances[msg.sender] += msg.value; }\n"
            "    function withdraw() public {\n"
            "        uint256 amount = balances[msg.sender];\n"
            '        (bool ok, ) = msg.sender.call{value: amount}("");\n'
            "        require(ok);\n"
            "        balances[msg.sender] = 0;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        plan = sandbox.plan(
            tool="slither",
            binary="slither",
            argv=[str(project), "--json", "-", "--fail-none"],
        )
        assert plan.sandboxed is True
        assert plan.network == "none"
        assert f"{CONTAINER_WORKDIR}/contracts" in plan.argv
        assert plan.argv[plan.argv.index(SHARED_IMAGE) + 1] == "slither"

        proc = self.run(plan)
        assert proc.returncode == 0, proc.stderr[-2000:]
        report = json.loads(proc.stdout)
        assert report["success"] is True
        checks = {d["check"] for d in report["results"]["detectors"]}
        assert "reentrancy-eth" in checks, checks

    def test_a_tool_the_image_lacks_falls_back_visibly(self, tmp_path: Path) -> None:
        """Not hypothetical: the Dockerfile's aderyn/gobuster/subzy steps are
        allowed to fail, and this image was built without them."""
        sandbox = self.real(tmp_path)
        absent = next(
            (
                name
                for name in ("subzy", "aderyn", "gobuster", "dirsearch", "retire")
                if shutil.which(name) and not sandbox.binary_in_image(SHARED_IMAGE, name)
            ),
            None,
        )
        if absent is None:
            pytest.skip("no host binary that this build of the image also lacks")

        plan = sandbox.plan(tool=absent, binary=absent, argv=["--help"])

        assert plan.sandboxed is False
        assert "not executable inside" in plan.fallback_reason
        assert sandbox.fallback_report() == [{"tool": absent, "reason": plan.fallback_reason}]


class TestHostPathNeverReachesTheContainer:
    """An absolute host path has no meaning inside an image.

    `guarded_run` resolved a tool's identity with `resolve_binary()`, which
    returns an absolute HOST path, and passed that single value to
    `Sandbox.plan()` as `binary`. The container branch then asked
    `command -v /usr/bin/amass` inside an image that keeps amass in
    /usr/local/bin, concluded it was absent, and fell back to the host.

    amass, cloud_enum, commix, garak and jaeles all escaped the sandbox this
    way. Every other marked tool passed only because its host and image paths
    happened to coincide — so the bug was invisible right up until an image
    layout differed. Found by running the toolchain against a live target;
    no test and no `doctor` run would have shown it, because both were asking
    about the host.
    """

    def test_container_check_uses_the_name_not_the_host_path(self, tmp_path) -> None:
        from cordon.control_plane.sandbox import Sandbox, SandboxConfig

        asked: list[str] = []

        class Probing(Sandbox):
            def runtime_available(self) -> bool:
                return True

            def image_present(self, image: str) -> bool:
                return True

            def binary_in_image(self, image: str, binary: str) -> bool:
                asked.append(binary)
                return not binary.startswith("/")

        sandbox = Probing(
            SandboxConfig.from_dict(
                {"mode": "docker", "default_image": "example:latest",
                 "verify_image_binary": True, "fallback_to_host": True}
            ),
            workspace=tmp_path,
        )
        plan = sandbox.plan(
            tool="amass",
            binary="amass",
            host_binary="/usr/bin/amass",
            argv=["-version"],
        )
        assert asked == ["amass"], f"container was asked about {asked}, not the bare name"
        assert plan.sandboxed, "resolved host path must not push the tool onto the host"

    def test_host_fallback_still_uses_the_resolved_path(self, tmp_path) -> None:
        """The identity-resolved path is the whole point on the host branch."""
        from cordon.control_plane.sandbox import Sandbox, SandboxConfig

        sandbox = Sandbox(
            SandboxConfig.from_dict({"mode": "none", "fallback_to_host": True}),
            workspace=tmp_path,
        )
        real = tmp_path / "httpx-real"
        real.write_text("#!/bin/sh\necho ok\n")
        real.chmod(0o755)

        plan = sandbox.plan(
            tool="httpx", binary="httpx", host_binary=str(real), argv=["-version"]
        )
        assert not plan.sandboxed
        assert str(real) in " ".join(plan.argv), (
            "host execution must use the identity-resolved binary, not PATH order"
        )
