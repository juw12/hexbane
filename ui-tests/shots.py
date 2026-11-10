"""Screenshots of the Scan page (and console-error check) in headless Edge.

    python ui-tests/shots.py [out_dir]     -> scan-empty-dark.png, scan-fail-dark.png, scan-fail-light.png, scan-disguised-dark.png, scan-base64-dark.png, scan-phone.png
Exit 1 if the page logs a JavaScript error.
"""

import functools
import http.server
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"



def launch_options() -> dict:
    """Edge locally (Windows); plain Playwright Chromium in CI (HEXBANE_BROWSER=chromium)."""
    if os.environ.get("HEXBANE_BROWSER", "msedge") == "chromium":
        return {"headless": True}
    return {"channel": "msedge", "headless": True}

def serve():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "web"))
    handler.log_message = lambda *a: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def main() -> int:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    server, base = serve()
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_options())
        for theme in ("dark", "light"):
            page = browser.new_page(viewport={"width": 1280, "height": 900}, color_scheme=theme)
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.goto(base + "#/scan")
            page.wait_for_selector(".scan-hero")
            if theme == "dark":
                page.screenshot(path=str(OUT / "scan-empty-dark.png"), full_page=True)
            page.click('button[data-sample="poisoned"]')
            page.wait_for_selector("#scan-verdict")
            page.screenshot(path=str(OUT / f"scan-fail-{theme}.png"), full_page=True)
            if theme == "dark":
                # Disguised text: the decoded instruction and the copyable fix are shown.
                page.click('button[data-sample="disguised"]')
                page.wait_for_selector("text=Disguised text")
                page.screenshot(path=str(OUT / "scan-disguised-dark.png"), full_page=True)
                # Base64 payload (HB105): the decoded content is shown under the finding.
                page.click('button[data-sample="base64"]')
                page.wait_for_selector(".hidden-text")
                page.screenshot(path=str(OUT / "scan-base64-dark.png"), full_page=True)
            page.close()
        phone = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2, color_scheme="dark")
        phone.on("pageerror", lambda e: errors.append(str(e)))
        phone.goto(base + "#/scan")
        phone.click('button[data-sample="hidden"]')
        phone.wait_for_selector("#scan-verdict")
        phone.screenshot(path=str(OUT / "scan-phone.png"), full_page=True)
        browser.close()
    server.shutdown()
    for e in errors:
        print("JS error:", e)
    print(f"screenshots in {OUT}; {len(errors)} JS errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
