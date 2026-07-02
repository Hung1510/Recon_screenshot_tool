# Recon Tool — Phase 1

Bulk reconnaissance screenshotter for Windows 10/11. Feed it a list of URLs; it
visits each one in a headless Chrome instance, captures a 1920×1080 screenshot,
detects login pages / admin panels, fingerprints web technologies, and builds a
self-contained HTML gallery with live search and filters.

Think of it as a small, hackable version of EyeWitness / gowitness.

> **Authorised use only.** Point this at assets you own or have written
> permission to test. Bulk-visiting third-party sites can trip abuse defences
> and, depending on your jurisdiction, laws.

---

## What it does

- **Concurrency** — `ThreadPoolExecutor` with a configurable worker count.
  Each worker thread keeps **one** Chrome instance and reuses it across the URLs
  it handles (far faster than one browser per URL). Configurable per-request
  delay for rate limiting.
- **Screenshots** — headless Chrome (`--headless=new`), 1920×1080, via Selenium.
  ChromeDriver is auto-installed by `webdriver-manager` (no PATH setup). Use
  `--no-headless` to watch it work.
- **Login detection** — `<input type="password">`, login keywords in the title
  and visible text, and common credential field names.
- **Admin detection** — anchor `href`s and page source scanned for `/admin`,
  `/administrator`, `/wp-admin`, `/dashboard`, `/login`, and more.
- **Technology fingerprinting** — a built-in signature engine (response headers,
  cookies, and the rendered DOM) detecting CMS (WordPress, Joomla, Drupal,
  Shopify…), JS frameworks (React, Vue, Angular, Next.js…), servers (Nginx,
  Apache, IIS, Cloudflare…), languages, and analytics. **No dependency on the
  dead `python-Wappalyzer` package.**
- **Blank-page detection** — optional, via OpenCV pixel-variance. Degrades
  gracefully if OpenCV isn't installed.
- **Crash-safe + resume** — every result is appended to `results.jsonl` as it
  finishes. `--resume` picks up the latest session and skips finished URLs.
- **Outputs** — a timestamped `recon_scan_YYYYMMDD_HHMMSS/` folder containing
  `screenshots/`, `results.json`, `errors.log`, and `index.html`.

---

## Setup (Windows)

1. Install **Python 3.10+** and **Google Chrome**.
2. In the project folder:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

`opencv-python` and `numpy` are optional — the tool runs without them, just
without blank-page detection.

---

## Usage

```cmd
python recon_tool.py
```

On first run it creates `urls.txt` if missing, then prompts for worker count and
delay (press Enter for defaults).

### Flags

| Flag | Meaning | Default |
|------|---------|---------|
| `--urls PATH` | input file | `urls.txt` |
| `--workers N` | concurrent workers | `5` |
| `--delay S` | per-thread delay (seconds) | `0.5` |
| `--timeout S` | page-load timeout | `15` |
| `--no-headless` | show the browser (debug) | off |
| `--resume` | resume latest session, skip finished URLs | off |
| `--driver-path PATH` | explicit `chromedriver.exe` (skip webdriver-manager) | — |
| `--yes` | use defaults, no prompts | off |

Examples:
```cmd
python recon_tool.py --workers 8 --delay 0.25 --yes
python recon_tool.py --resume
python recon_tool.py --no-headless --workers 1        :: debugging
```

When it finishes it prints the path to `index.html` — open it in any browser.

---

## Output layout

```
recon_scan_20260703_142300/
├── screenshots/
│   ├── example.com.png
│   └── github.com_login.png
├── results.json      # full metadata, array of records
├── results.jsonl     # append-only log (source of truth for --resume)
├── errors.log        # per-URL failures with stack traces
└── index.html        # the gallery
```

Each record: `url`, `screenshot`, `title`, `is_login`, `is_admin`,
`technologies`, `status`, `error`, `blank`, `timestamp`.

---

## Notes & tuning

- **Throughput:** ~100 URLs in a few minutes with 5 workers, depending on how
  many pages hit the 15 s timeout. Raise `--workers` if your machine has the RAM
  (each Chrome ≈ 150–300 MB).
- **Technology accuracy** is intentionally conservative — header/DOM signatures,
  not a full browser-extension fingerprint set. Add your own entries to
  `TECH_SIGNATURES` at the top of `recon_tool.py`; the format is documented
  inline.
- **Adding detections:** `analyze_page()`, `detect_login()`, and `detect_admin()`
  are small and pure — easy to extend.

## Phase 2 (not included)

OCR + local-LLM (Ollama) screenshot analysis is deliberately left out. It's best
run as a separate offline pass over the saved screenshots rather than inline in
the concurrent scrape loop (the LLM step serialises on one GPU and would wreck
throughput). The code is structured so that layer can be bolted on without
touching the screenshot logic.
