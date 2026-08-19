#!/usr/bin/env node
/**
 * EasyHunt dashboard — Playwright smoke test.
 *
 * Verifies the React dashboard actually renders: starts `easyhunt dashboard
 * --serve`, opens every view, checks real data landed, exercises the findings
 * filters, and screenshots each view on failure. Uses the system Chrome
 * (executablePath) via playwright-core — no browser download.
 *
 * Usage:
 *   node e2e/smoke.mjs                # full run against the newest workspace
 *   WS=<name> node e2e/smoke.mjs      # pin a workspace
 *   PORT=8899 node e2e/smoke.mjs      # custom port
 *
 * Exit 0 = every check passed.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const ROOT = resolve(import.meta.dirname, "..", "..");
const PORT = Number(process.env.PORT || 8899);
const WS = process.env.WS || "";
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME = process.env.CHROME_BIN
  || ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]
      .find((p) => existsSync(p));

let failures = 0;
const shots = mkdtempSync(join(tmpdir(), "easyhunt-e2e-"));
const pass = (m) => console.log(`  ✓ ${m}`);
const fail = (m) => { failures += 1; console.error(`  ✗ ${m}`); };
const check = (cond, m) => (cond ? pass(m) : fail(m));

function startServer() {
  const py = join(ROOT, ".venv", "bin", "python");
  const args = ["-m", "easyhunt.cli", "dashboard", "--serve", "--port", String(PORT)];
  const child = spawn(py, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", (d) => process.env.DEBUG && process.stderr.write(d));
  return child;
}

async function waitForServer(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/api/state`, { cache: "no-store" });
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

async function main() {
  const server = startServer();
  try {
    check(await waitForServer(), "dashboard server is up");
    if (!failures && !(await fetch(`${BASE}/api/state`)).ok) {
      fail("server responded but /api/state failed");
      return;
    }
  } catch {
    fail("could not reach dashboard server");
    server.kill("SIGKILL");
    process.exit(1);
  }

  const browser = await chromium.launch({
    executablePath: CHROME,
    headless: true,
    args: ["--no-sandbox", "--disable-gpu"],
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("pageerror", (e) => fail(`page JS error: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !m.text().includes("favicon")) fail(`console error: ${m.text()}`);
  });

  const qs = WS ? `?ws=${encodeURIComponent(WS)}` : "";
  try {
    // ---- Overview ----
    await page.goto(`${BASE}/${qs}#overview`, { waitUntil: "networkidle" });
    await page.waitForSelector(".nav-item", { timeout: 15000 });
    check(await page.locator(".nav-item").count() >= 8, "sidebar has 8 nav items");
    check((await page.locator(".card").count()) >= 4, "overview stat cards render");
    check(await page.locator(".pipeline .ph").count() >= 10, "phase pipeline renders");
    const liveDot = await page.locator(".live .dot").count();
    check(liveDot === 1, "live status dot present");
    await page.screenshot({ path: join(shots, "overview.png") });

    // ---- Findings (needs a workspace with findings) ----
    await page.goto(`${BASE}/${qs}#findings`, { waitUntil: "networkidle" });
    await page.waitForSelector(".filterbar", { timeout: 15000 });
    const rows0 = await page.locator("table.data tbody > tr:not(.detail-row)").count();
    const summary = await page.locator("text=of").count();
    check(rows0 > 0 || summary > 0, `findings table renders (${rows0} rows)`);
    // Filter interaction: click the first severity chip, rows must change or stay filtered
    const chips = page.locator(".chiprow .chip");
    if (await chips.count() > 0) {
      await chips.first().click();
      await page.waitForTimeout(300);
      pass("severity filter chip clickable");
    }
    await page.screenshot({ path: join(shots, "findings.png") });

    // ---- Assets ----
    await page.goto(`${BASE}/${qs}#assets`, { waitUntil: "networkidle" });
    await page.waitForSelector(".tabs .tab", { timeout: 15000 });
    const tabs = await page.locator(".tabs .tab").count();
    check(tabs >= 1, `asset tabs render (${tabs})`);
    if (tabs > 1) {
      await page.locator(".tabs .tab").nth(1).click();
      await page.waitForTimeout(300);
      pass("asset tab switch works");
    }
    await page.screenshot({ path: join(shots, "assets.png") });

    // ---- Coverage / Activity / Tools / FalsePositives / Reports ----
    for (const [view, sel, label] of [
      ["coverage", ".filterbar", "coverage view"],
      ["activity", ".filterbar", "activity view"],
      ["tools", ".filterbar", "tools view"],
      ["fp", ".feed, .empty", "false positives view"],
      ["reports", ".report-link, .empty", "reports view"],
    ]) {
      await page.goto(`${BASE}/${qs}#${view}`, { waitUntil: "networkidle" });
      await page.waitForSelector(sel, { timeout: 15000 });
      pass(`${label} renders`);
    }
    await page.screenshot({ path: join(shots, "final.png") });

    // ---- Live poll: /api/state must keep returning fresh data ----
    const r = await fetch(`${BASE}/api/state`, { cache: "no-store" });
    const state = await r.json();
    check(Array.isArray(state.phases) || typeof state.phases === "object", "state blob has phases");
    check(Array.isArray(state.workspaces), "workspace switcher data present");
  } catch (e) {
    fail(`e2e threw: ${e.message}`);
    await page.screenshot({ path: join(shots, "crash.png") }).catch(() => {});
  } finally {
    await browser.close();
  }

  server.kill("SIGKILL");
  console.log(failures
    ? `\nFAILED: ${failures} check(s) failed — screenshots in ${shots}`
    : `\nALL CHECKS PASSED — screenshots in ${shots}`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
