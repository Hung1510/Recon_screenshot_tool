#!/usr/bin/env python3
"""
recon_tool.py  -  Phase 1
=========================
Bulk reconnaissance screenshot + detection + gallery tool for Windows 10/11.

Given a list of URLs (urls.txt), this tool:
  * Visits each URL in a headless Chrome instance (multi-threaded).
  * Saves a 1920x1080 screenshot per URL.
  * Detects login pages and admin panels from the rendered HTML.
  * Fingerprints web technologies (CMS / JS frameworks / servers / analytics)
    from the response headers, cookies and rendered DOM.
  * Flags blank / failed pages.
  * Writes results.json + a self-contained, responsive HTML gallery with
    live search and filters.

Design notes / differences from a naive first draft:
  * The abandoned `python-Wappalyzer` package is NOT used. Technology
    detection is a small, self-contained signature engine (headers + DOM).
  * OpenCV is used for something that actually works -- blank-page detection
    -- not fake "login form template matching". It is fully optional.
  * Each worker THREAD keeps ONE Chrome instance (thread-local) and reuses it
    across the URLs it handles. Much faster than one browser per URL, and
    still satisfies "each thread runs its own Chrome".
  * Crash-safe: every result is appended to results.jsonl as it completes, so
    `--resume` can skip finished URLs and rebuild outputs from what survived.

Only run this against assets you own or are explicitly authorised to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import re
import sys
import threading
import time
import traceback
from html import escape as _html_escape
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Third-party imports (hard deps)
# ---------------------------------------------------------------------------
try:
    import requests
    from bs4 import BeautifulSoup
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from tqdm import tqdm
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError as exc:  # pragma: no cover - guidance only
    print("[!] Missing a required package: {}".format(exc))
    print("    Install everything with:  pip install -r requirements.txt")
    sys.exit(1)

# Pillow is used for error/blank placeholder screenshots.
try:
    from PIL import Image, ImageDraw, ImageFont
    _HAVE_PIL = True
except ImportError:
    _HAVE_PIL = False

# OpenCV + numpy are optional (blank-page detection only).
try:
    import cv2  # noqa: F401
    import numpy as np
    _HAVE_CV2 = True
except ImportError:
    _HAVE_CV2 = False

# Silence noisy TLS warnings from the best-effort header fetch.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_WORKERS = 5
DEFAULT_DELAY = 0.5          # seconds a worker sleeps after each URL
DEFAULT_TIMEOUT = 15         # Chrome page-load timeout (seconds)
WINDOW_W, WINDOW_H = 1920, 1080
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LOGIN_KEYWORDS = ["login", "log in", "sign in", "signin", "log-in", "sign-in",
                  "sign on", "authenticate", "my account"]
ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/wp-login",
               "/dashboard", "/login", "/cpanel", "/phpmyadmin",
               "/manager", "/panel", "/console"]

DEFAULT_URLS = [
    "https://example.com",
    "https://www.wikipedia.org",
    "https://github.com/login",
]


# ---------------------------------------------------------------------------
# Technology fingerprint engine  (replaces the dead python-Wappalyzer)
# ---------------------------------------------------------------------------
# Each entry: name -> {"headers": {header: regex}, "cookies": [regex],
#                      "html": [regex], "scripts": [regex], "meta": [regex]}
# Matching is case-insensitive. Any single hit tags the technology.
TECH_SIGNATURES = {
    # --- CMS ---------------------------------------------------------------
    "WordPress": {"html": [r"wp-content", r"wp-includes"],
                  "meta": [r"WordPress"],
                  "headers": {"link": r"wp-json"}},
    "Joomla": {"meta": [r"Joomla"], "html": [r"/media/jui/", r"option=com_"]},
    "Drupal": {"headers": {"x-generator": r"Drupal"},
               "meta": [r"Drupal"], "html": [r"sites/default/files", r"/core/misc/drupal"]},
    "Ghost": {"meta": [r"Ghost \d"], "html": [r"ghost/api", r"content/images"]},
    "Shopify": {"html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
                "headers": {"x-shopify-stage": r".+"}},
    "Wix": {"html": [r"static\.wixstatic\.com", r"X-Wix"],
            "headers": {"x-wix-request-id": r".+"}},
    "Squarespace": {"html": [r"static1\.squarespace\.com", r"squarespace\.com"]},
    "Magento": {"html": [r"/static/version\d", r"Mage\.", r"mage/cookies"],
                "cookies": [r"X-Magento"]},
    # --- JS frameworks / libraries ----------------------------------------
    "React": {"html": [r"data-reactroot", r"data-reactid", r"__REACT_DEVTOOLS",
                       r"/react(?:\.production)?\.min\.js"]},
    "Next.js": {"html": [r"/_next/static", r"__NEXT_DATA__"],
                "headers": {"x-powered-by": r"Next\.js"}},
    "Vue.js": {"html": [r"data-v-[0-9a-f]{8}", r"__vue__", r"vue(?:\.min)?\.js"]},
    "Nuxt.js": {"html": [r"__NUXT__", r"/_nuxt/"]},
    "Angular": {"html": [r"ng-version", r"ng-app", r"angular(?:\.min)?\.js"]},
    "Svelte": {"html": [r"svelte-[0-9a-z]{6}"]},
    "jQuery": {"scripts": [r"jquery[.-][\d.]+(?:\.min)?\.js", r"/jquery\.js"]},
    "Bootstrap": {"html": [r"bootstrap(?:\.min)?\.css", r"class=\"[^\"]*\b(?:navbar|col-md-|btn-primary)\b"]},
    "Tailwind CSS": {"html": [r"class=\"[^\"]*\b(?:flex|grid|px-\d|py-\d|bg-\w+-\d00)\b"]},
    # --- Web servers / proxies / CDNs -------------------------------------
    "Nginx": {"headers": {"server": r"nginx"}},
    "Apache": {"headers": {"server": r"Apache"}},
    "Microsoft IIS": {"headers": {"server": r"IIS", "x-powered-by": r"ASP\.NET"}},
    "LiteSpeed": {"headers": {"server": r"LiteSpeed"}},
    "Cloudflare": {"headers": {"server": r"cloudflare", "cf-ray": r".+"}},
    "Amazon CloudFront": {"headers": {"via": r"CloudFront", "x-amz-cf-id": r".+"}},
    "Varnish": {"headers": {"via": r"varnish", "x-varnish": r".+"}},
    # --- Languages / runtimes ---------------------------------------------
    "PHP": {"headers": {"x-powered-by": r"PHP", "set-cookie": r"PHPSESSID"}},
    "ASP.NET": {"headers": {"x-aspnet-version": r".+", "x-powered-by": r"ASP\.NET"},
                "cookies": [r"ASP\.NET_SessionId"]},
    "Express": {"headers": {"x-powered-by": r"Express"}},
    "Node.js": {"headers": {"x-powered-by": r"Express|Next\.js"}},
    # --- Analytics / tag managers -----------------------------------------
    "Google Analytics": {"html": [r"google-analytics\.com/(?:ga|analytics)", r"gtag\(", r"GoogleAnalyticsObject"]},
    "Google Tag Manager": {"html": [r"googletagmanager\.com/gtm"]},
    "Cloudflare Turnstile": {"html": [r"challenges\.cloudflare\.com/turnstile"]},
    "reCAPTCHA": {"html": [r"google\.com/recaptcha", r"grecaptcha"]},
}


def _search_any(patterns, text):
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def fingerprint_technologies(html: str, headers: dict, cookies: str) -> list:
    """Return a sorted list of detected technology names.

    `headers` is a dict of lower-cased header name -> value.
    `cookies` is the raw Set-Cookie / cookie string (may be '').
    """
    html = html or ""
    headers = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    cookies = cookies or ""
    detected = set()

    for name, sig in TECH_SIGNATURES.items():
        hit = False
        # header signatures
        for hname, hpat in sig.get("headers", {}).items():
            val = headers.get(hname.lower(), "")
            if val and re.search(hpat, val, re.IGNORECASE):
                hit = True
                break
        # cookie signatures
        if not hit and _search_any(sig.get("cookies", []), cookies):
            hit = True
        # meta generator / html / script signatures all scan the body
        if not hit and _search_any(sig.get("meta", []), html):
            hit = True
        if not hit and _search_any(sig.get("html", []), html):
            hit = True
        if not hit and _search_any(sig.get("scripts", []), html):
            hit = True
        if hit:
            detected.add(name)

    # Node.js is implied by Express/Next; avoid double noise
    if "Node.js" in detected and not ({"Express", "Next.js"} & detected):
        detected.discard("Node.js")
    return sorted(detected)


# ---------------------------------------------------------------------------
# Driver management (thread-local: one Chrome per worker thread, reused)
# ---------------------------------------------------------------------------
_thread_local = threading.local()
_driver_registry = []          # every driver we create, for clean shutdown
_registry_lock = threading.Lock()
_log_lock = threading.Lock()
_jsonl_lock = threading.Lock()


def setup_driver(headless: bool = True, timeout: int = DEFAULT_TIMEOUT,
                 driver_path: str | None = None) -> "webdriver.Chrome":
    """Create and return a configured Chrome WebDriver instance."""
    opts = ChromeOptions()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--window-size={},{}".format(WINDOW_W, WINDOW_H))
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-notifications")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--log-level=3")
    opts.add_argument("--user-agent={}".format(USER_AGENT))
    opts.add_experimental_option("excludeSwitches", ["enable-logging", "enable-automation"])

    if driver_path:
        service = ChromeService(executable_path=driver_path)
    else:
        # Selenium 4.6+ ships Selenium Manager; webdriver-manager is a safe
        # fallback that also pins the correct driver on Windows.
        service = ChromeService(ChromeDriverManager().install())

    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(timeout)
    try:
        driver.set_window_size(WINDOW_W, WINDOW_H)
    except WebDriverException:
        pass
    return driver


def get_thread_driver(cfg: dict) -> "webdriver.Chrome":
    """Return this thread's driver, creating it on first use."""
    drv = getattr(_thread_local, "driver", None)
    if drv is None:
        drv = setup_driver(
            headless=cfg["headless"],
            timeout=cfg["timeout"],
            driver_path=cfg.get("driver_path"),
        )
        _thread_local.driver = drv
        with _registry_lock:
            _driver_registry.append(drv)
    return drv


def shutdown_all_drivers():
    with _registry_lock:
        for drv in _driver_registry:
            try:
                drv.quit()
            except Exception:
                pass
        _driver_registry.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sanitize_filename(url: str) -> str:
    """Turn a URL into a safe, mostly-readable file stem."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    stem = (parsed.netloc + parsed.path).strip("/")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem)
    stem = stem.strip("_") or "page"
    if len(stem) > 120:
        stem = stem[:120]
    return stem


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return url


def load_urls(path: str) -> list:
    """Read urls.txt: strip blanks, comments, duplicates; preserve order."""
    seen, out = set(), []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = normalize_url(line)
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


def log_error(output_dir: str, url: str, message: str):
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[{}] {}  ::  {}\n".format(ts, url, message.replace("\n", " | "))
    with _log_lock:
        with open(os.path.join(output_dir, "errors.log"), "a",
                  encoding="utf-8") as fh:
            fh.write(line)


def make_placeholder(path: str, url: str, message: str):
    """Write a 1920x1080 placeholder PNG for a failed/blank page."""
    if not _HAVE_PIL:
        # Touch an empty file so the gallery still has a target.
        open(path, "ab").close()
        return
    img = Image.new("RGB", (WINDOW_W, WINDOW_H), (24, 26, 31))
    draw = ImageDraw.Draw(img)
    try:
        font_big = ImageFont.truetype("arial.ttf", 54)
        font_small = ImageFont.truetype("arial.ttf", 30)
    except Exception:
        font_big = ImageFont.load_default()
        font_small = ImageFont.load_default()
    draw.text((80, 440), "\u26a0  No screenshot", fill=(230, 90, 90), font=font_big)
    draw.text((80, 530), url[:90], fill=(180, 190, 200), font=font_small)
    draw.text((80, 580), message[:110], fill=(120, 130, 140), font=font_small)
    img.save(path)


def is_blank_screenshot(path: str) -> bool:
    """Detect an effectively-blank screenshot via pixel variance (OpenCV).

    Returns False if OpenCV is unavailable or the check fails -- we never
    let this optional feature break the pipeline.
    """
    if not _HAVE_CV2:
        return False
    try:
        img = cv2.imread(path)
        if img is None:
            return True
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        # Low std-dev => almost uniform image => blank/white/error page.
        return bool(float(gray.std()) < 3.0)
    except Exception:
        return False


def fetch_headers(url: str, timeout: int) -> tuple:
    """Best-effort header + cookie fetch for fingerprinting.

    Returns (headers_dict, cookie_string). Never raises.
    """
    try:
        resp = requests.get(
            url, timeout=timeout, verify=False, allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        headers = dict(resp.headers)
        cookie_str = "; ".join(
            "{}={}".format(c.name, c.value) for c in resp.cookies
        )
        set_cookie = resp.headers.get("set-cookie", "")
        cookie_str = (cookie_str + " " + set_cookie).strip()
        return headers, cookie_str
    except Exception:
        return {}, ""


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def detect_login(soup: "BeautifulSoup", page_source: str, title: str,
                 visible_text: str) -> bool:
    # Strongest signal: a password field.
    if soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
        return True
    hay = " ".join([title or "", visible_text or ""]).lower()
    if any(kw in hay for kw in LOGIN_KEYWORDS):
        return True
    # Common login form field names.
    for inp in soup.find_all("input"):
        name = (inp.get("name") or "") + " " + (inp.get("id") or "")
        if re.search(r"\b(user(name)?|email|passwd|password)\b", name, re.I):
            # only count if there is also a submit-ish control nearby
            return bool(soup.find(["button", "input"], attrs={"type": re.compile(r"submit", re.I)})
                        or soup.find("form"))
    return False


def detect_admin(soup: "BeautifulSoup", page_source: str, url: str) -> bool:
    src = (page_source or "").lower()
    u = (url or "").lower()
    for path in ADMIN_PATHS:
        if path in u:
            return True
    # Scan anchor hrefs.
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        if any(path in href for path in ADMIN_PATHS):
            return True
    # Fall back to a raw source scan for admin path strings.
    return any(path in src for path in ADMIN_PATHS)


def analyze_page(driver: "webdriver.Chrome", url: str) -> dict:
    """Return {title, is_login, is_admin, technologies} from the rendered page.

    Technology detection here is DOM-only; header-based signals are merged in
    later by process_url via fetch_headers(). Kept separate so this function
    matches the required signature and stays pure/testable.
    """
    page_source = driver.page_source or ""
    soup = BeautifulSoup(page_source, "lxml")
    title = (driver.title or "").strip()
    try:
        visible_text = soup.get_text(" ", strip=True)[:20000]
    except Exception:
        visible_text = ""

    is_login = detect_login(soup, page_source, title, visible_text)
    is_admin = detect_admin(soup, page_source, url)
    technologies = fingerprint_technologies(page_source, {}, "")

    return {
        "title": title,
        "is_login": is_login,
        "is_admin": is_admin,
        "technologies": technologies,
        "_page_source": page_source,   # consumed by process_url, then dropped
    }


# ---------------------------------------------------------------------------
# Per-URL pipeline
# ---------------------------------------------------------------------------
def process_url(url: str, output_dir: str, session_id: str, cfg: dict) -> dict:
    """Full pipeline for a single URL. Never raises; returns a record dict."""
    shots_dir = os.path.join(output_dir, "screenshots")
    stem = sanitize_filename(url)
    shot_rel = os.path.join("screenshots", stem + ".png")
    shot_abs = os.path.join(shots_dir, stem + ".png")

    record = {
        "url": url,
        "screenshot": shot_rel.replace("\\", "/"),
        "title": "",
        "is_login": False,
        "is_admin": False,
        "technologies": [],
        "status": "ok",
        "error": "",
        "blank": False,
        "session_id": session_id,
        "timestamp": _dt.datetime.now().isoformat(timespec="seconds"),
    }

    driver = None
    try:
        driver = get_thread_driver(cfg)
        try:
            driver.get(url)
        except TimeoutException:
            # Page-load timed out but partial DOM may exist; keep going.
            record["status"] = "timeout"
        # small settle for late-rendering SPAs
        time.sleep(min(2.0, cfg.get("settle", 1.0)))

        try:
            driver.save_screenshot(shot_abs)
        except WebDriverException as exc:
            make_placeholder(shot_abs, url, "screenshot failed: {}".format(exc))
            record["status"] = "screenshot_error"

        analysis = analyze_page(driver, url)
        page_source = analysis.pop("_page_source", "")
        record.update(analysis)

        # Merge header/cookie-based technology signals.
        headers, cookies = fetch_headers(url, cfg["timeout"])
        header_tech = fingerprint_technologies(page_source, headers, cookies)
        record["technologies"] = sorted(set(record["technologies"]) | set(header_tech))

        # Blank-page check (OpenCV, optional).
        if os.path.exists(shot_abs) and is_blank_screenshot(shot_abs):
            record["blank"] = True
            if record["status"] == "ok":
                record["status"] = "blank"

    except Exception as exc:  # catch-all: one bad URL must not kill the run
        record["status"] = "error"
        record["error"] = "{}: {}".format(type(exc).__name__, exc)
        log_error(output_dir, url, traceback.format_exc())
        if not os.path.exists(shot_abs):
            make_placeholder(shot_abs, url, record["error"])
        # A driver may be wedged; drop it so the thread rebuilds a fresh one.
        try:
            if driver is not None:
                driver.quit()
        except Exception:
            pass
        _thread_local.driver = None
    finally:
        if cfg.get("delay"):
            time.sleep(cfg["delay"])

    # Persist immediately (crash-safe).
    with _jsonl_lock:
        with open(os.path.join(output_dir, "results.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


# ---------------------------------------------------------------------------
# Gallery
# ---------------------------------------------------------------------------
def generate_gallery(data_list: list, output_dir: str) -> str:
    """Build a self-contained responsive HTML gallery. Returns its path."""
    total = len(data_list)
    n_login = sum(1 for d in data_list if d.get("is_login"))
    n_admin = sum(1 for d in data_list if d.get("is_admin"))
    n_err = sum(1 for d in data_list if d.get("status") not in ("ok", "blank", "timeout"))

    cards = []
    for d in data_list:
        tags = []
        if d.get("is_login"):
            tags.append('<span class="tag tag-login">\U0001F510 Login</span>')
        if d.get("is_admin"):
            tags.append('<span class="tag tag-admin">\u2699\uFE0F Admin</span>')
        if d.get("blank"):
            tags.append('<span class="tag tag-blank">\u25A1 Blank</span>')
        status = d.get("status", "ok")
        if status not in ("ok", "blank"):
            tags.append('<span class="tag tag-err">\u26A0 {}</span>'.format(_html_escape(status)))

        techs = "".join(
            '<span class="badge">{}</span>'.format(_html_escape(t))
            for t in d.get("technologies", [])
        )
        title = _html_escape(d.get("title") or "(no title)")
        url = _html_escape(d.get("url", ""))
        shot = _html_escape(d.get("screenshot", ""))

        # Data blob used by the live filter (lower-cased).
        search_blob = _html_escape(" ".join([
            d.get("url", ""), d.get("title", ""),
            " ".join(d.get("technologies", [])),
            "login" if d.get("is_login") else "",
            "admin" if d.get("is_admin") else "",
            status,
        ]).lower())

        flags = " ".join(filter(None, [
            "login" if d.get("is_login") else "",
            "admin" if d.get("is_admin") else "",
            "error" if status not in ("ok", "blank", "timeout") else "",
            "blank" if d.get("blank") else "",
        ]))

        cards.append(CARD_TEMPLATE.format(
            search=search_blob, flags=flags, shot=shot, url=url,
            title=title, tags="".join(tags) or "", techs=techs or
            '<span class="badge badge-muted">none detected</span>',
        ))

    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = PAGE_TEMPLATE.format(
        total=total, n_login=n_login, n_admin=n_admin, n_err=n_err,
        generated=ts, cards="\n".join(cards),
    )
    out_path = os.path.join(output_dir, "index.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path


CARD_TEMPLATE = """    <article class="card" data-search="{search}" data-flags="{flags}">
      <a class="shot" href="{shot}" target="_blank" rel="noopener">
        <img loading="lazy" src="{shot}" alt="{title}">
      </a>
      <div class="meta">
        <div class="tags">{tags}</div>
        <a class="url" href="{url}" target="_blank" rel="noopener" title="{url}">{url}</a>
        <div class="title">{title}</div>
        <div class="badges">{techs}</div>
      </div>
    </article>"""


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Gallery</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c232d; --line:#2a3441;
    --fg:#e6edf3; --muted:#8b949e; --accent:#3fb950; --accent2:#58a6ff;
    --login:#d29922; --admin:#f85149; --blank:#6e7681;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font-family:'Inter',system-ui,sans-serif; }}
  header {{ position:sticky; top:0; z-index:10; background:rgba(13,17,23,.92);
    backdrop-filter:blur(8px); border-bottom:1px solid var(--line); padding:16px 24px; }}
  .titlebar {{ display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }}
  h1 {{ font-family:'JetBrains Mono',monospace; font-size:20px; margin:0;
    letter-spacing:.5px; }}
  h1 .dot {{ color:var(--accent); }}
  .gen {{ color:var(--muted); font-size:12px; font-family:'JetBrains Mono',monospace; }}
  .stats {{ display:flex; gap:18px; margin:12px 0; flex-wrap:wrap; font-size:13px;
    color:var(--muted); font-family:'JetBrains Mono',monospace; }}
  .stats b {{ color:var(--fg); }}
  .stats .s-login b {{ color:var(--login); }}
  .stats .s-admin b {{ color:var(--admin); }}
  .stats .s-err b {{ color:var(--admin); }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:6px; }}
  #search {{ flex:1 1 320px; min-width:220px; background:var(--panel2);
    border:1px solid var(--line); color:var(--fg); padding:10px 14px;
    border-radius:8px; font-size:14px; font-family:inherit; }}
  #search:focus {{ outline:none; border-color:var(--accent2); }}
  .chips {{ display:flex; gap:6px; flex-wrap:wrap; }}
  .chip {{ background:var(--panel2); border:1px solid var(--line); color:var(--muted);
    padding:8px 14px; border-radius:20px; cursor:pointer; font-size:13px;
    font-family:'JetBrains Mono',monospace; user-select:none; transition:.15s; }}
  .chip:hover {{ border-color:var(--accent2); color:var(--fg); }}
  .chip.active {{ background:var(--accent2); border-color:var(--accent2); color:#0d1117; font-weight:600; }}
  main {{ padding:24px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
    gap:18px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    overflow:hidden; display:flex; flex-direction:column; transition:.15s; }}
  .card:hover {{ border-color:var(--accent2); transform:translateY(-2px);
    box-shadow:0 8px 24px rgba(0,0,0,.4); }}
  .shot {{ display:block; background:#000; height:200px; overflow:hidden; }}
  .shot img {{ width:100%; height:200px; object-fit:cover; object-position:top;
    display:block; }}
  .meta {{ padding:12px 14px; display:flex; flex-direction:column; gap:6px; }}
  .tags {{ display:flex; gap:6px; flex-wrap:wrap; min-height:2px; }}
  .tag {{ font-size:11px; font-weight:600; padding:2px 8px; border-radius:6px;
    font-family:'JetBrains Mono',monospace; }}
  .tag-login {{ background:rgba(210,153,34,.15); color:var(--login);
    border:1px solid rgba(210,153,34,.4); }}
  .tag-admin {{ background:rgba(248,81,73,.15); color:var(--admin);
    border:1px solid rgba(248,81,73,.4); }}
  .tag-blank {{ background:rgba(110,118,129,.15); color:var(--blank);
    border:1px solid rgba(110,118,129,.4); }}
  .tag-err {{ background:rgba(248,81,73,.12); color:var(--admin);
    border:1px solid rgba(248,81,73,.35); }}
  .url {{ color:var(--accent2); font-size:12px; text-decoration:none;
    font-family:'JetBrains Mono',monospace; white-space:nowrap; overflow:hidden;
    text-overflow:ellipsis; }}
  .url:hover {{ text-decoration:underline; }}
  .title {{ font-size:14px; font-weight:500; line-height:1.35;
    display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
    overflow:hidden; }}
  .badges {{ display:flex; gap:5px; flex-wrap:wrap; margin-top:2px; }}
  .badge {{ font-size:10px; background:var(--panel2); border:1px solid var(--line);
    color:var(--muted); padding:2px 7px; border-radius:5px;
    font-family:'JetBrains Mono',monospace; }}
  .badge-muted {{ opacity:.5; }}
  .empty {{ color:var(--muted); text-align:center; padding:60px 0;
    font-family:'JetBrains Mono',monospace; }}
</style>
</head>
<body>
<header>
  <div class="titlebar">
    <h1><span class="dot">&gt;</span> recon_gallery</h1>
    <span class="gen">generated {generated}</span>
  </div>
  <div class="stats">
    <span class="s-total"><b>{total}</b> targets</span>
    <span class="s-login"><b>{n_login}</b> login pages</span>
    <span class="s-admin"><b>{n_admin}</b> admin panels</span>
    <span class="s-err"><b>{n_err}</b> errors</span>
  </div>
  <div class="controls">
    <input id="search" type="search" placeholder="filter by url, title, tag or technology...">
    <div class="chips">
      <span class="chip active" data-filter="all">all</span>
      <span class="chip" data-filter="login">login</span>
      <span class="chip" data-filter="admin">admin</span>
      <span class="chip" data-filter="error">errors</span>
      <span class="chip" data-filter="blank">blank</span>
    </div>
  </div>
</header>
<main>
  <div class="grid" id="grid">
{cards}
  </div>
  <div class="empty" id="empty" style="display:none;">no matches</div>
</main>
<script>
  const grid = document.getElementById('grid');
  const cards = Array.from(grid.querySelectorAll('.card'));
  const search = document.getElementById('search');
  const empty = document.getElementById('empty');
  const chips = Array.from(document.querySelectorAll('.chip'));
  let activeFilter = 'all';

  function apply() {{
    const q = search.value.trim().toLowerCase();
    let shown = 0;
    cards.forEach(c => {{
      const blob = c.dataset.search || '';
      const flags = c.dataset.flags || '';
      const matchText = !q || blob.includes(q);
      const matchFilter = activeFilter === 'all' || flags.includes(activeFilter);
      const vis = matchText && matchFilter;
      c.style.display = vis ? '' : 'none';
      if (vis) shown++;
    }});
    empty.style.display = shown ? 'none' : 'block';
  }}

  search.addEventListener('input', apply);
  chips.forEach(ch => ch.addEventListener('click', () => {{
    chips.forEach(x => x.classList.remove('active'));
    ch.classList.add('active');
    activeFilter = ch.dataset.filter;
    apply();
  }}));
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Session / resume helpers
# ---------------------------------------------------------------------------
def load_existing_records(output_dir: str) -> list:
    path = os.path.join(output_dir, "results.jsonl")
    records = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def find_latest_session(base: str = ".") -> str | None:
    dirs = [d for d in os.listdir(base)
            if d.startswith("recon_scan_") and os.path.isdir(os.path.join(base, d))]
    if not dirs:
        return None
    dirs.sort()
    return os.path.join(base, dirs[-1])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Bulk recon screenshot + detection + HTML gallery (Phase 1).")
    p.add_argument("--urls", default="urls.txt", help="input file (one URL per line)")
    p.add_argument("--workers", type=int, default=None, help="concurrent workers")
    p.add_argument("--delay", type=float, default=None, help="per-thread delay (s)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="page load timeout (s)")
    p.add_argument("--no-headless", action="store_true", help="show the browser (debug)")
    p.add_argument("--resume", action="store_true",
                   help="resume the most recent session, skipping finished URLs")
    p.add_argument("--driver-path", default=None,
                   help="explicit chromedriver.exe path (skips webdriver-manager)")
    p.add_argument("--yes", action="store_true", help="use defaults, no prompts")
    return p.parse_args(argv)


def prompt_int(msg, default):
    try:
        raw = input("{} [{}]: ".format(msg, default)).strip()
        return int(raw) if raw else default
    except (ValueError, EOFError, KeyboardInterrupt):
        return default


def prompt_float(msg, default):
    try:
        raw = input("{} [{}]: ".format(msg, default)).strip()
        return float(raw) if raw else default
    except (ValueError, EOFError, KeyboardInterrupt):
        return default


def main(argv=None):
    args = parse_args(argv)

    banner = r"""
   ___  ___  ___ ___  _ __   ___  ___  __ _ _ __
  / __|/ _ \/ __/ _ \| '_ \ / _ \/ __|/ _` | '_ \
  \__ \  __/ (_| (_) | | | |  __/\__ \ (_| | | | |
  |___/\___|\___\___/|_| |_|\___||___/\__,_|_| |_|   phase 1
"""
    print(banner)
    print("  [i] AI Mode: Disabled (Phase 2 not installed)")
    print("  [i] OpenCV blank-detection: {}".format("ON" if _HAVE_CV2 else "off (opencv not installed)"))
    print("  [i] Placeholder images (Pillow): {}".format("ON" if _HAVE_PIL else "off (pillow not installed)"))
    print("  [!] Only scan assets you own or are authorised to test.\n")

    # --- input file --------------------------------------------------------
    if not os.path.exists(args.urls):
        with open(args.urls, "w", encoding="utf-8") as fh:
            fh.write("# One URL per line. Lines starting with # are ignored.\n")
            fh.write("\n".join(DEFAULT_URLS) + "\n")
        print("  [+] '{}' not found -- created a starter file with examples.".format(args.urls))
        print("      Edit it and re-run.\n")
        return 0

    urls = load_urls(args.urls)
    if not urls:
        print("  [!] No usable URLs in '{}'.".format(args.urls))
        return 1

    # --- worker / delay config --------------------------------------------
    if args.workers is None:
        workers = DEFAULT_WORKERS if args.yes else prompt_int("  Concurrent workers", DEFAULT_WORKERS)
    else:
        workers = args.workers
    if args.delay is None:
        delay = DEFAULT_DELAY if args.yes else prompt_float("  Delay per request (s)", DEFAULT_DELAY)
    else:
        delay = args.delay
    workers = max(1, workers)

    # --- session directory (new or resumed) -------------------------------
    if args.resume:
        output_dir = find_latest_session()
        if not output_dir:
            print("  [!] --resume given but no recon_scan_* folder found. Starting fresh.")
            args.resume = False
    if not args.resume:
        session_id = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(".", "recon_scan_{}".format(session_id))
    else:
        session_id = os.path.basename(output_dir).replace("recon_scan_", "")

    os.makedirs(os.path.join(output_dir, "screenshots"), exist_ok=True)

    done_urls = set()
    if args.resume:
        existing = load_existing_records(output_dir)
        done_urls = {r.get("url") for r in existing}
        print("  [i] Resuming '{}' -- {} URLs already done.".format(output_dir, len(done_urls)))

    todo = [u for u in urls if u not in done_urls]
    print("  [i] {} URLs total | {} to process | {} workers | {:.1f}s delay\n".format(
        len(urls), len(todo), workers, delay))

    if not todo:
        print("  [i] Nothing left to process. Rebuilding gallery from existing results.")

    cfg = {
        "headless": not args.no_headless,
        "timeout": args.timeout,
        "delay": delay,
        "settle": 1.0,
        "driver_path": args.driver_path,
    }

    # --- process -----------------------------------------------------------
    start = time.time()
    try:
        if todo:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {
                    ex.submit(process_url, u, output_dir, session_id, cfg): u
                    for u in todo
                }
                for _ in tqdm(concurrent.futures.as_completed(futures),
                              total=len(futures), desc="  scanning", unit="url",
                              ncols=78):
                    pass
    except KeyboardInterrupt:
        print("\n  [!] Interrupted. Partial results saved; re-run with --resume.")
    finally:
        shutdown_all_drivers()

    elapsed = time.time() - start

    # --- assemble outputs --------------------------------------------------
    records = load_existing_records(output_dir)
    # Stable order: follow the original urls.txt ordering where possible.
    order = {u: i for i, u in enumerate(urls)}
    records.sort(key=lambda r: order.get(r.get("url"), 1e9))

    with open(os.path.join(output_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False, indent=2)

    index_path = generate_gallery(records, output_dir)

    ok = sum(1 for r in records if r.get("status") in ("ok", "blank", "timeout"))
    err = len(records) - ok
    print("\n  [+] Done in {:.1f}s  ({} ok, {} errors)".format(elapsed, ok, err))
    print("  [+] Results : {}".format(os.path.abspath(os.path.join(output_dir, "results.json"))))
    print("  [+] Gallery : {}".format(os.path.abspath(index_path)))
    print("\n  Open the gallery in your browser:")
    print("      {}\n".format(os.path.abspath(index_path)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
