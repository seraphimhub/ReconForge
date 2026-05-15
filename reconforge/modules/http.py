from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlsplit

import httpx

from reconforge.core.context import ReconContext
from reconforge.core.models import Finding


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class HTTPModule:
    name = "http"
    category = "active"
    description = "HTTP/HTTPS fingerprinting, headers, redirects, cookies, robots.txt, and security headers."
    active = True

    async def run(self, target: str, ctx: ReconContext) -> Finding:
        candidates = self._candidate_urls(target)
        attempts: list[dict[str, object]] = []
        for url in candidates:
            result = await self._fetch(url, ctx)
            attempts.append(result)
            if result.get("ok"):
                return Finding(module=self.name, target=target, status="ok", data=result)

        return Finding(
            module=self.name,
            target=target,
            status="error",
            data={"attempts": attempts},
            error="No HTTP endpoint responded successfully.",
        )

    def _candidate_urls(self, target: str) -> list[str]:
        if "://" in target:
            return [target]
        return [f"https://{target}", f"http://{target}"]

    async def _fetch(self, url: str, ctx: ReconContext) -> dict[str, object]:
        config = ctx.config["http"]
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(
                url,
                follow_redirects=bool(config["follow_redirects"]),
            )
        except httpx.HTTPError as exc:
            return {"url": url, "ok": False, "error": str(exc)}

        body = response.text[: int(config["max_body_bytes"])]
        headers = {key.lower(): value for key, value in response.headers.items()}
        data: dict[str, object] = {
            "url": str(response.url),
            "ok": True,
            "status_code": response.status_code,
            "reason_phrase": response.reason_phrase,
            "http_version": response.http_version,
            "redirect_chain": [str(item.url) for item in response.history],
            "title": self._extract_title(body),
            "headers": self._interesting_headers(headers),
            "security_headers": self._security_headers(headers),
            "cookies": self._cookies(response),
            "technologies": self._detect_technologies(headers, body),
        }

        if config.get("fetch_robots"):
            data["robots"] = await self._fetch_robots(str(response.url), ctx)
        return data

    def _extract_title(self, body: str) -> str | None:
        match = TITLE_RE.search(body)
        if not match:
            return None
        title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
        return title[:200] if title else None

    def _interesting_headers(self, headers: dict[str, str]) -> dict[str, str]:
        interesting = [
            "server",
            "x-powered-by",
            "via",
            "location",
            "content-type",
            "cache-control",
            "x-cache",
            "cf-ray",
        ]
        return {name: headers[name] for name in interesting if name in headers}

    def _security_headers(self, headers: dict[str, str]) -> dict[str, object]:
        expected = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        present = {name: headers[name] for name in expected if name in headers}
        missing = [name for name in expected if name not in headers]
        return {"present": present, "missing": missing}

    def _cookies(self, response: httpx.Response) -> list[dict[str, object]]:
        cookies = []
        for cookie in response.cookies.jar:
            cookies.append(
                {
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": "httponly" in {key.lower() for key in cookie._rest.keys()},
                    "samesite": cookie._rest.get("SameSite") or cookie._rest.get("samesite"),
                }
            )
        return cookies

    def _detect_technologies(self, headers: dict[str, str], body: str) -> list[str]:
        tech: set[str] = set()
        combined = "\n".join([headers.get("server", ""), headers.get("x-powered-by", ""), body[:50000]])
        lowered = combined.lower()

        hints = {
            "nginx": "nginx",
            "apache": "apache",
            "cloudflare": "cloudflare",
            "wordpress": "wp-content",
            "drupal": "drupal",
            "joomla": "joomla",
            "next.js": "__next",
            "nuxt": "__nuxt",
            "react": "react",
            "laravel": "laravel",
            "php": "php",
            "asp.net": "asp.net",
        }
        for label, needle in hints.items():
            if needle in lowered:
                tech.add(label)

        generator = META_GENERATOR_RE.search(body)
        if generator:
            tech.add(f"generator:{generator.group(1).strip()[:80]}")
        return sorted(tech)

    async def _fetch_robots(self, url: str, ctx: ReconContext) -> dict[str, object]:
        parsed = urlsplit(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            await ctx.limiter.wait()
            response = await ctx.client.get(robots_url, follow_redirects=True)
            if response.status_code >= 400:
                return {"url": robots_url, "found": False, "status_code": response.status_code}
            lines = response.text.splitlines()
            interesting = [
                line.strip()
                for line in lines
                if line.lower().startswith(("user-agent:", "disallow:", "allow:", "sitemap:"))
            ]
            return {
                "url": robots_url,
                "found": True,
                "status_code": response.status_code,
                "directives": interesting[:100],
            }
        except httpx.HTTPError as exc:
            return {"url": robots_url, "found": False, "error": str(exc)}

