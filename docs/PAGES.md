# GitHub Pages — publish `preview.html` as a website (2026)

This repo is Pages-ready. No build step. Two files matter:

- `preview.html` (root) — local preview, open in any browser.
- `docs/index.html` (identical copy) — what GitHub Pages serves.

## Deploy in 4 clicks

1. Push this repo to GitHub as **public**.
2. GitHub → **Settings → Pages → Build and deployment → Deploy from a branch**.
3. Branch: `main`, folder: `/docs` → **Save**.
4. Wait ~60s → open `https://<you>.github.io/<repo>/`.

That URL renders the hero, live numbers, benchmark bars, beginner guide,
user stories, demo instructions, **interactive 12-question quiz**, and this guide.

## Custom domain (optional)

- Settings → Pages → Custom domain → enter `lab.yourdomain.com`.
- Add `CNAME` file in `docs/` containing the domain.
- DNS: `CNAME lab → <you>.github.io`. Enforce HTTPS.

## Local check before pushing

```bash
python3 scripts/capture_preview.py   # validates 12 questions + sections, renders PNGs if Playwright present
python3 -c "from html.parser import HTMLParser; HTMLParser().feed(open('preview.html').read()); print('HTML OK')"
```

## Videos / GIFs

- Put `assets/demo.gif` (<10 MB) and/or `assets/demo.mp4` in `assets/`.
- `preview.html` already embeds both with graceful fallback text if missing.
- Record with: `asciinema rec demo.cast` → `agg demo.cast assets/demo.gif`,
  or screen-record `bash scripts/run_all.sh` (clips: run / Docker / quiz).
- For MP4 over 25 MB, use GitHub Releases and link the release URL in `preview.html`.
