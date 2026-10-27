"""
x1vart Web Recon - Source Map Hunter (.js.map Reconstructor)
Detects and parses JavaScript Source Maps (.js.map) to reconstruct original
source file trees, unminified TypeScript/ES6 paths, developer comments, and internal credentials.
Strictly returns empty results if target has no source maps.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
import httpx

logger = logging.getLogger("x1vart.sourcemap")

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class SourceMapHunter:
    @staticmethod
    async def probe_sourcemap(js_url: str, js_code: str = "") -> Optional[Dict[str, Any]]:
        """
        Check if a source map exists for a given JavaScript file:
        1. Inspect `//# sourceMappingURL=` comment.
        2. Probe `{js_url}.map`.
        Verifies that returned content is strictly valid JSON containing 'sources'.
        """
        map_url = None

        # Check comment in JS code
        match = re.search(r"//[#@]\s*sourceMappingURL=([^\s]+)", js_code)
        if match:
            map_target = match.group(1).strip()
            if not map_target.startswith("data:"):
                map_url = urljoin(js_url, map_target)

        # Fallback to direct .map probe
        if not map_url:
            map_url = f"{js_url}.map"

        headers = {
            "User-Agent": CHROME_UA,
            "Accept": "application/json, text/plain, */*"
        }

        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
                resp = await client.get(map_url, headers=headers)
                
                # Ensure HTTP 200 and not an HTML custom 404 page
                if resp.status_code == 200:
                    text_start = resp.text.strip()[:50]
                    if not text_start.startswith("{"):
                        return None

                    try:
                        map_data = resp.json()
                        if not isinstance(map_data, dict) or "sources" not in map_data:
                            return None

                        sources = map_data.get("sources", [])
                        if not sources:
                            return None

                        file_count = len(sources)
                        sources_content = map_data.get("sourcesContent", [])
                        has_source_code = bool(sources_content and len(sources_content) > 0)

                        classified_files = []
                        for idx, s in enumerate(sources[:30]):
                            clean_path = s.replace("../", "").lstrip("./")
                            classified_files.append({
                                "file_path": clean_path,
                                "is_source_available": bool(sources_content and idx < len(sources_content) and sources_content[idx]),
                                "content_preview": (sources_content[idx][:200] + "...") if (sources_content and idx < len(sources_content) and sources_content[idx]) else None
                            })

                        return {
                            "js_url": js_url,
                            "map_url": map_url,
                            "version": map_data.get("version", 3),
                            "total_sources": file_count,
                            "has_unminified_code": has_source_code,
                            "source_files": classified_files,
                            "severity": "HIGH",
                            "advisory": f"Source map exposed at {map_url}! Allows complete reverse-engineering of {file_count} original source files."
                        }
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.debug(f"Source map check failed for {map_url}: {e}")

        return None

    async def scan_all_scripts(self, js_urls: List[str], js_files_map: Dict[str, str], **kwargs) -> List[Dict[str, Any]]:
        """
        Check all discovered JS files for exposed source maps concurrently.
        Strictly returns [] if no valid maps found on real targets.
        """
        results: List[Dict[str, Any]] = []
        for url in js_urls:
            code = js_files_map.get(url, "")
            res = await self.probe_sourcemap(url, code)
            if res:
                results.append(res)
        return results
