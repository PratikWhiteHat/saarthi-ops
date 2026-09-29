"""Playwright-backed helpers: authenticated login + the XSS execution oracle.

Both are optional — if Playwright is not installed the login helper returns no
cookies and the XSS oracle is simply absent, so reflected-XSS findings stay
suspected (the oracle never confirms on reflection alone). Kept out of the pure
engine modules so the core stays import-light and unit-testable offline.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

from saarthi2.vulnengine.models import InputSurface
from saarthi2.vulnengine.probe import build_base

# Defines a global the injected payloads call; we read back which markers fired.
_XSS_INIT = (
    "window.__saarthi_fired = [];"
    "window.__saarthi_xss = function(m){ window.__saarthi_fired.push(m); };"
)

_DEFAULT_USER_SEL = (
    "input[name='username'], input[name='user'], input[name='email'], "
    "input[type='email'], input[type='text']"
)
_DEFAULT_PASS_SEL = "input[name='password'], input[type='password']"
_DEFAULT_SUBMIT_SEL = (
    "input[type='submit'], button[type='submit'], input[name='Login'], "
    "button:has-text('Log in'), button:has-text('Login'), button:has-text('Sign in')"
)


def playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False
    return True


async def login(
    url: str,
    username: str,
    password: str,
    *,
    username_selector: str | None = None,
    password_selector: str | None = None,
    submit_selector: str | None = None,
) -> dict[str, str]:
    """Log in with a real headless browser; return the session cookies by name.

    Returns ``{}`` if Playwright is unavailable or the login fails, so the caller
    can proceed unauthenticated (or surface the problem) without crashing.
    """

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {}
    cookies: dict[str, str] = {}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.fill(username_selector or _DEFAULT_USER_SEL, username, timeout=8000)
            await page.fill(password_selector or _DEFAULT_PASS_SEL, password, timeout=8000)
            try:
                await page.click(submit_selector or _DEFAULT_SUBMIT_SEL, timeout=5000)
            except Exception:
                await page.keyboard.press("Enter")
            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            for c in await context.cookies():
                name = str(c.get("name", ""))
                if name:
                    cookies[name] = str(c.get("value", ""))
            await browser.close()
    except Exception:
        return cookies
    return cookies


def _get_url(surface: InputSurface, param: str, value: str) -> str:
    base = build_base(surface)
    if param is not None:
        base[param] = value
    parts = urlsplit(surface.url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(base), ""))


class PlaywrightXss:
    """The reflected-XSS execution oracle: navigate and check the marker fired."""

    def __init__(self, cookies: dict[str, str] | None = None) -> None:
        self._cookies = dict(cookies or {})

    async def __call__(
        self, surface: InputSurface, param: str | None, value: str, marker: str
    ) -> bool:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False
        if surface.method.upper() != "GET" or param is None:
            return False  # only GET reflection is driven here
        url = _get_url(surface, param, value)
        base = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                if self._cookies:
                    await context.add_cookies(
                        [{"name": n, "value": v, "url": base} for n, v in self._cookies.items()]
                    )
                await context.add_init_script(_XSS_INIT)
                page = await context.new_page()
                await page.goto(url, wait_until="networkidle", timeout=30000)
                fired = await page.evaluate("window.__saarthi_fired || []")
                await browser.close()
        except Exception:
            return False
        return marker in (fired or [])
