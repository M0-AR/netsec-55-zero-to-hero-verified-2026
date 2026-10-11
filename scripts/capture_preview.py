"""Capture preview.html screenshots via Playwright (verified).
Usage: python3 scripts/capture_preview.py
Outputs: assets/preview-hero.png (1280x900) + assets/preview-full.png
Also validates quiz count == 12 and key sections present.
"""
import pathlib, re
R = pathlib.Path(__file__).resolve().parents[1]
html = (R/"preview.html").read_text()
assert 'id="qbox"' in html and 'const QS=' in html, "quiz renderer missing"
# count QS entries: lines starting with ["Your or ["Sudden etc — simpler: count '["' in QS block
m = re.search(r"const QS=\[(.*?)\];", html, re.S)
assert m, "QS block missing"
qs = m.group(1)
# 12 questions each start with ["  (bracket+quote)
# each question contributes 2x '["' (outer + options array) → 12 questions = 24
n = qs.count('["')
print(f"quiz markers found: {n} → questions: {n//2}")
assert n//2 == 12, f"expected 12, got {n//2}"
for key in ["Beginner guide", "GitHub Pages", "Quickstart", "Benchmark", "user stories", "Demo"]:
    assert key.lower() in html.lower(), f"missing section {key}"
print("preview.html sections OK")

try:
    from playwright.sync_api import sync_playwright
except Exception as e:
    print(f"playwright not installed ({e}) — skipping render, HTML still valid")
    raise SystemExit(0)

out = R/"assets"; out.mkdir(exist_ok=True)
url = (R/"preview.html").as_uri()
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width":1280,"height":900})
    pg.goto(url, wait_until="networkidle")
    pg.wait_for_timeout(800)
    pg.screenshot(path=str(out/"preview-hero.png"))
    pg.screenshot(path=str(out/"preview-full.png"), full_page=True)
    b.close()
print("screenshots written to assets/")
