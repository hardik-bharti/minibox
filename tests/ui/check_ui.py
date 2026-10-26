#!/usr/bin/env python3
"""Drive the `minibox ui` page in a headless browser and screenshot it.

Usage: <python with playwright> tests/ui/check_ui.py [OUT_DIR]

Optional: needs Playwright for Python and its Chromium, which the rest of
the project doesn't. Starts `bin/minibox ui` on a spare port, clicks
through every panel (each demo runs for real), and saves screenshots in
light and dark mode to OUT_DIR (default: a new temp dir). Fails if the page
logs a JavaScript error or a demo doesn't produce its result.
"""

import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PORT = 7180
URL = f"http://127.0.0.1:{PORT}/"


def wait_idle(page, timeout=90_000):
    """Wait until the status pill says Ready again (the demo finished)."""
    page.wait_for_function("document.querySelector('#status').classList.contains('busy')", timeout=5_000)
    page.wait_for_function("document.querySelector('#status').classList.contains('idle')", timeout=timeout)


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="minibox-ui-shots-"))
    out.mkdir(parents=True, exist_ok=True)
    server = subprocess.Popen([str(ROOT / "bin" / "minibox"), "ui", "--addr", f"127.0.0.1:{PORT}"],
                              cwd=ROOT, stderr=subprocess.PIPE, text=True)
    errors = []
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(URL + "api/info", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            # The page's CSP forbids eval, which Playwright's string predicates
            # in wait_for_function rely on; bypass it for the test only.
            ctx = browser.new_context(viewport={"width": 1280, "height": 900}, bypass_csp=True)
            page = ctx.new_page()
            page.on("console", lambda m: m.type == "error" and errors.append(m.text))
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(URL)
            page.wait_for_function("document.querySelector('#status').classList.contains('idle')")

            def shot(name):
                page.screenshot(path=str(out / f"{name}.png"), full_page=True)

            # Phase 1
            page.click("button[data-run=isolation]"); wait_idle(page)
            assert page.locator("#iso-viz table tr.diff").count() >= 6, "isolation table missing"
            shot("1-isolation")
            # Phase 2: the memory hog (default 64m)
            page.click("#tab-limits"); page.click("#lim-run"); wait_idle(page)
            assert "OOM" in page.inner_text("#lim-facts"), "memory outcome missing"
            shot("2-limits-memory")
            page.click("[data-kind=cpu]"); page.select_option("#lim-value", "0.25"); page.click("#lim-run"); wait_idle(page)
            shot("2-limits-cpu")
            # Phase 5
            page.click("#tab-profile"); page.click("button[data-run=profile]"); wait_idle(page)
            assert page.locator("#prof-grid span.on").count() > 5, "policy grid empty"
            page.select_option("#enf-workload", "list"); page.click("button[data-run=enforce]"); wait_idle(page)
            assert "Failed under the policy" in page.inner_text("#enf-result"), "enforce result missing"
            shot("3-profile")
            # Phase 6: two quick rows
            page.click("#tab-attacks")
            for name in ("mount", "raw-socket"):
                page.click(f"tr[data-attack={name}] button:has-text('Run')"); wait_idle(page)
            page.click("tr[data-attack=raw-socket] td[data-config=baseline] button")
            shot("4-attacks")
            # Filter walkthrough
            page.click("#tab-filter"); page.select_option("#flt-syscall", "clone:newuser"); page.click("#flt-show")
            page.wait_for_selector("#flt-verdict .state")
            shot("5-filter")
            # Dark mode and a phone-width view of the busiest panel
            page.emulate_media(color_scheme="dark"); page.click("#tab-limits"); shot("6-dark-limits")
            page.set_viewport_size({"width": 390, "height": 844}); page.click("#tab-profile"); shot("7-phone-profile")
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    print(f"screenshots in {out}")
    if errors:
        print("JavaScript errors:\n  " + "\n  ".join(errors))
        sys.exit(1)
    print("ui check passed")


if __name__ == "__main__":
    main()
