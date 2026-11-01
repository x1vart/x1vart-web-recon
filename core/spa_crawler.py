"""
x1vart - Headless Browser Crawler for Dynamic SPA (JS Hunter Upgrade)
Utilizes Playwright to execute and render modern Single Page Applications (React, Vue, Angular).
Captures dynamically imported webpack/vite chunk scripts, sourcemaps, and API endpoints via network interception.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, Browser, Page, Response, Route
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

logger = logging.getLogger("x1vart.spa_crawler")


@dataclass
class SpaCrawlResult:
    target_url: str
    discovered_scripts: List[str] = field(default_factory=list)
    sourcemaps: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    page_title: str = ""
    dom_scripts: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    engine_used: str = "playwright_headless"
    error: Optional[str] = None


class DynamicSpaCrawler:
    """
    High-performance headless crawler tailored for dynamic Single Page Applications (SPAs).
    Optimizes memory by aborting non-essential resources (images, fonts, stylesheets).
    """

    BLOCKED_RESOURCE_TYPES: Set[str] = {"image", "media", "font", "stylesheet"}
    BLOCKED_EXTENSIONS: tuple = (
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm"
    )

    SCRIPT_MIME_TYPES: Set[str] = {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript"
    }

    def __init__(
        self,
        headless: bool = True,
        navigation_timeout_ms: int = 25000,
        wait_after_scroll_ms: int = 1500,
        user_agent: Optional[str] = None
    ):
        self.headless = headless
        self.navigation_timeout_ms = navigation_timeout_ms
        self.wait_after_scroll_ms = wait_after_scroll_ms
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 x1vart-Recon/2.0"
        )

    async def _handle_route(self, route: Any):
        """Aborts images, fonts, stylesheets, and media requests to accelerate JavaScript discovery."""
        req = route.request
        url_lower = req.url.lower()

        if req.resource_type in self.BLOCKED_RESOURCE_TYPES or any(url_lower.endswith(ext) for ext in self.BLOCKED_EXTENSIONS):
            await route.abort()
        else:
            await route.continue_()

    async def crawl(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
        auto_scroll: bool = True,
        trigger_menus: bool = True
    ) -> SpaCrawlResult:
        """
        Launches headless browser, navigates to SPA URL, hooks network responses,
        triggers dynamic chunk loading via scroll & clicks, and extracts all JS scripts and source maps.
        """
        start_time = asyncio.get_event_loop().time()
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        discovered_scripts: Set[str] = set()
        sourcemaps: Set[str] = set()
        api_endpoints: Set[str] = set()
        dom_scripts: Set[str] = set()
        page_title = ""

        if not HAS_PLAYWRIGHT:
            logger.warning("[SPA Crawler] Playwright not installed. Falling back to HTTP response parser.")
            return await self._fallback_http_crawl(url, custom_headers)

        try:
            async with async_playwright() as p:
                browser: Browser = await p.chromium.launch(
                    headless=self.headless,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--mute-audio"
                    ]
                )

                context = await browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=True,
                    viewport={"width": 1440, "height": 900},
                    extra_http_headers=custom_headers or {}
                )

                page: Page = await context.new_page()
                page.set_default_navigation_timeout(self.navigation_timeout_ms)

                # 1. Block heavy assets
                await page.route("**/*", self._handle_route)

                # 2. Intercept network responses to capture dynamic chunks
                async def on_response(response: Response):
                    try:
                        resp_url = response.url
                        ct = response.headers.get("content-type", "").lower()

                        # Capture scripts & sourcemaps
                        if any(ct.startswith(m) for m in self.SCRIPT_MIME_TYPES) or resp_url.endswith((".js", ".mjs")):
                            discovered_scripts.add(resp_url)
                            # Probe for accompanying .map
                            if not resp_url.endswith(".map"):
                                sourcemaps.add(f"{resp_url}.map")
                        elif resp_url.endswith(".map"):
                            sourcemaps.add(resp_url)

                        # Check for SourceMappingUrl header
                        sm_header = response.headers.get("sourcemappingurl")
                        if sm_header:
                            sourcemaps.add(urljoin(resp_url, sm_header))

                        # Capture XHR/Fetch API endpoints
                        if response.request.resource_type in ("fetch", "xhr") or "application/json" in ct:
                            parsed_ep = urlparse(resp_url)
                            if parsed_ep.path and parsed_ep.path != "/":
                                api_endpoints.add(resp_url)
                    except Exception as err:
                        logger.debug(f"[SPA Response Hook Error] {err}")

                page.on("response", on_response)

                # 3. Navigate to SPA target
                logger.info(f"[*] [SPA Crawler] Loading dynamic SPA: {url}")
                await page.goto(url, wait_until="domcontentloaded")
                page_title = await page.title()

                # Give hydration a quick pause
                await page.wait_for_timeout(1000)

                # 4. Extract script tags directly present in DOM
                script_elements = await page.eval_on_selector_all(
                    "script[src]",
                    "elements => elements.map(el => el.getAttribute('src'))"
                )
                for src in script_elements:
                    if src:
                        full_script_url = urljoin(url, src)
                        dom_scripts.add(full_script_url)
                        discovered_scripts.add(full_script_url)
                        sourcemaps.add(f"{full_script_url}.map")

                # 5. Trigger Lazy Loading via Auto-Scroll
                if auto_scroll:
                    logger.debug("[SPA Crawler] Performing auto-scroll to trigger lazy chunks...")
                    await page.evaluate("""async () => {
                        await new Promise((resolve) => {
                            let totalHeight = 0;
                            const distance = 400;
                            const timer = setInterval(() => {
                                const scrollHeight = document.body.scrollHeight;
                                window.scrollBy(0, distance);
                                totalHeight += distance;
                                if (totalHeight >= scrollHeight || totalHeight >= 4000) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 100);
                        });
                    }""")
                    await page.wait_for_timeout(self.wait_after_scroll_ms)

                # 6. Trigger Dynamic Menu/Router clicks (Non-navigating buttons)
                if trigger_menus:
                    logger.debug("[SPA Crawler] Triggering menu toggles for dynamic route chunks...")
                    try:
                        # Find menu, tab, dropdown buttons that don't submit forms
                        clickable_selectors = [
                            "button[aria-expanded='false']",
                            "button.navbar-toggler",
                            "[role='tab']",
                            "a[href^='#/']"
                        ]
                        for selector in clickable_selectors:
                            elements = await page.query_selector_all(selector)
                            for el in elements[:3]:  # Trigger top 3 to avoid infinite loops
                                try:
                                    if await el.is_visible():
                                        await el.click(timeout=800)
                                        await page.wait_for_timeout(300)
                                except Exception:
                                    pass
                    except Exception:
                        pass

                # Final wait for pending background network fetches
                await page.wait_for_timeout(1000)
                await context.close()
                await browser.close()

        except Exception as exc:
            logger.error(f"[SPA Crawler Failed] {url}: {exc}")
            return SpaCrawlResult(
                target_url=url,
                discovered_scripts=sorted(list(discovered_scripts)),
                sourcemaps=sorted(list(sourcemaps)),
                api_endpoints=sorted(list(api_endpoints)),
                dom_scripts=sorted(list(dom_scripts)),
                page_title=page_title,
                execution_time_seconds=round(asyncio.get_event_loop().time() - start_time, 2),
                error=str(exc)
            )

        duration = round(asyncio.get_event_loop().time() - start_time, 2)
        logger.info(f"[SPA Crawler Done] Discovered {len(discovered_scripts)} scripts, {len(sourcemaps)} sourcemaps in {duration}s.")
        return SpaCrawlResult(
            target_url=url,
            discovered_scripts=sorted(list(discovered_scripts)),
            sourcemaps=sorted(list(sourcemaps)),
            api_endpoints=sorted(list(api_endpoints)),
            dom_scripts=sorted(list(dom_scripts)),
            page_title=page_title,
            execution_time_seconds=duration,
            engine_used="playwright_headless"
        )

    async def _fallback_http_crawl(self, url: str, custom_headers: Optional[Dict[str, str]]) -> SpaCrawlResult:
        """Graceful fallback when Playwright headless browser binaries are not installed."""
        import httpx
        from bs4 import BeautifulSoup

        start_time = asyncio.get_event_loop().time()
        scripts: Set[str] = set()
        sourcemaps: Set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True, headers=custom_headers) as client:
                res = await client.get(url)
                soup = BeautifulSoup(res.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else ""

                for tag in soup.find_all("script", src=True):
                    src = tag["src"].strip()
                    if src:
                        full = urljoin(url, src)
                        scripts.add(full)
                        sourcemaps.add(f"{full}.map")

                # Search inline scripts for dynamic webpack chunk imports: e.g. "static/js/" + e + ".chunk.js"
                chunk_matches = re.findall(r'["\']([a-zA-Z0-9_\-\./]+\.chunk\.js)["\']', res.text)
                for chunk in chunk_matches:
                    full_chunk = urljoin(url, chunk)
                    scripts.add(full_chunk)
                    sourcemaps.add(f"{full_chunk}.map")

                return SpaCrawlResult(
                    target_url=url,
                    discovered_scripts=sorted(list(scripts)),
                    sourcemaps=sorted(list(sourcemaps)),
                    page_title=title,
                    dom_scripts=sorted(list(scripts)),
                    execution_time_seconds=round(asyncio.get_event_loop().time() - start_time, 2),
                    engine_used="httpx_static_fallback"
                )
        except Exception as e:
            return SpaCrawlResult(
                target_url=url,
                execution_time_seconds=round(asyncio.get_event_loop().time() - start_time, 2),
                engine_used="httpx_static_fallback",
                error=str(e)
            )
