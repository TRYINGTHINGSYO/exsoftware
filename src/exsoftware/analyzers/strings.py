from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import Evidence, Finding
from ..rules.indicators import (
    ASCII_RE,
    DOMAIN_RE,
    EMAIL_RE,
    INTERESTING_PATTERNS,
    IPV4_RE,
    POSIX_PATH_RE,
    REGISTRY_RE,
    URL_RE,
    UTF16_RE,
    WIN_PATH_RE,
)
from .base import Analyzer

MAX_STORED_STRINGS = 800
MAX_STRING_CHARS = 240
MAX_INDICATORS = 200

_COMPILED_PATTERNS = [
    (ident, title, re.compile(pattern), summary)
    for ident, title, pattern, summary in INTERESTING_PATTERNS
]


def _clip(text: str) -> str:
    if len(text) <= MAX_STRING_CHARS:
        return text
    return text[: MAX_STRING_CHARS - 1] + "…"


def extract_strings(data: bytes) -> list[dict]:
    found: list[dict] = []
    for match in ASCII_RE.finditer(data):
        found.append(
            {
                "encoding": "ascii",
                "offset": match.start(),
                "value": match.group().decode("ascii", "replace"),
            }
        )
    for match in UTF16_RE.finditer(data):
        found.append(
            {
                "encoding": "utf-16le",
                "offset": match.start(),
                "value": match.group().decode("utf-16le", "replace"),
            }
        )
    found.sort(key=lambda item: item["offset"])
    return found


def _is_boring_ip(ip: str) -> bool:
    parts = [int(p) for p in ip.split(".")]
    if ip in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
        return False
    if parts[0] == 0:
        return True
    # Version-like 1.2.3.4 with all tiny numbers is kept but callers can deprioritize.
    return False


def classify_string(value: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "paths": [],
        "registry": [],
        "interesting": [],
    }
    for match in URL_RE.finditer(value):
        hits["urls"].append(match.group(0).rstrip(").,;]"))
    for match in EMAIL_RE.finditer(value):
        hits["emails"].append(match.group(0))
    for match in IPV4_RE.finditer(value):
        ip = match.group(0)
        if not _is_boring_ip(ip):
            hits["ips"].append(ip)
    if not hits["urls"]:
        for match in DOMAIN_RE.finditer(value):
            hits["domains"].append(match.group(0).lower())
    for match in WIN_PATH_RE.finditer(value):
        hits["paths"].append(match.group(0))
    for match in POSIX_PATH_RE.finditer(value):
        hits["paths"].append(match.group(0))
    for match in REGISTRY_RE.finditer(value):
        hits["registry"].append(match.group(0))
    for ident, _title, regex, _summary in _COMPILED_PATTERNS:
        if regex.search(value):
            hits["interesting"].append(ident)
    return hits


class StringsAnalyzer(Analyzer):
    name = "strings"
    title = "Strings and indicators"

    def analyze(self, ctx):
        raw = extract_strings(ctx.data)
        ascii_count = sum(1 for item in raw if item["encoding"] == "ascii")
        utf16_count = sum(1 for item in raw if item["encoding"] == "utf-16le")

        urls: list[dict] = []
        domains: list[str] = []
        ips: list[str] = []
        emails: list[str] = []
        paths: list[str] = []
        registry: list[str] = []
        pattern_hits: dict[str, list[dict]] = {}
        stored = []

        for item in raw:
            value = item["value"]
            classified = classify_string(value)
            interesting = bool(
                classified["urls"]
                or classified["ips"]
                or classified["emails"]
                or classified["registry"]
                or classified["interesting"]
                or classified["paths"]
            )
            record = {
                "offset": item["offset"],
                "encoding": item["encoding"],
                "length": len(value),
                "value": _clip(value),
                "interesting": interesting,
            }
            if interesting or len(stored) < MAX_STORED_STRINGS:
                stored.append(record)
            elif interesting:
                stored.append(record)

            for url in classified["urls"]:
                if len(urls) < MAX_INDICATORS:
                    parsed = urlparse(url)
                    urls.append(
                        {
                            "url": url[:500],
                            "host": parsed.hostname,
                            "scheme": parsed.scheme,
                            "offset": item["offset"],
                        }
                    )
                    if parsed.hostname:
                        domains.append(parsed.hostname.lower())
            domains.extend(classified["domains"])
            ips.extend(classified["ips"])
            emails.extend(classified["emails"])
            paths.extend(classified["paths"])
            registry.extend(classified["registry"])
            for ident in classified["interesting"]:
                pattern_hits.setdefault(ident, []).append(
                    {"offset": item["offset"], "value": _clip(value)}
                )

        def unique(values: list[str]) -> list[str]:
            seen: set[str] = set()
            out = []
            for value in values:
                key = value.lower() if isinstance(value, str) else value
                if key in seen:
                    continue
                seen.add(key)
                out.append(value)
                if len(out) >= MAX_INDICATORS:
                    break
            return out

        domains = unique(domains)
        ips = unique(ips)
        emails = unique(emails)
        paths = unique(paths)
        registry = unique(registry)
        # Prefer interesting strings first in the stored list, keep order otherwise.
        stored.sort(key=lambda item: (not item["interesting"], item["offset"]))
        stored = stored[:MAX_STORED_STRINGS]

        findings: list[Finding] = []
        if urls:
            findings.append(
                Finding(
                    id="strings.urls",
                    title=f"{len(urls)} URL(s) extracted from strings",
                    summary="The file contains URL-like strings. They were not fetched.",
                    category="network",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["urls", "network"],
                    evidence=[
                        Evidence(
                            kind="string",
                            summary="Extracted URL",
                            analyzer=self.name,
                            location=f"offset {item['offset']}",
                            value=item["url"],
                        )
                        for item in urls[:12]
                    ],
                )
            )
        if ips:
            findings.append(
                Finding(
                    id="strings.ipv4",
                    title=f"{len(ips)} IPv4 address(es) in strings",
                    summary="Dotted IPv4 literals were found. Some may be versions or other numeric data.",
                    category="network",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["ip", "network"],
                    evidence=[
                        Evidence(kind="string", summary="IPv4 literal", analyzer=self.name, value=ip)
                        for ip in ips[:12]
                    ],
                )
            )
        if emails:
            findings.append(
                Finding(
                    id="strings.emails",
                    title=f"{len(emails)} email address(es) in strings",
                    summary="Email-like strings were extracted.",
                    category="metadata",
                    severity="info",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["email"],
                    evidence=[
                        Evidence(kind="string", summary="Email", analyzer=self.name, value=email)
                        for email in emails[:12]
                    ],
                )
            )
        if registry:
            findings.append(
                Finding(
                    id="strings.registry",
                    title="Registry path strings",
                    summary="The file contains Windows registry path strings.",
                    category="system",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["registry"],
                    evidence=[
                        Evidence(kind="string", summary="Registry path", analyzer=self.name, value=path)
                        for path in registry[:12]
                    ],
                )
            )

        for ident, title, regex, summary in _COMPILED_PATTERNS:
            hits = pattern_hits.get(ident) or []
            if not hits:
                continue
            if ident in {"appdata", "temp-path", "api-key-word"}:
                severity = "info"
            elif ident in {"http-url", "ftp-url", "ip-literal", "email"}:
                continue
            elif ident in {"iex", "encoded-command", "frombase64", "eval", "private-key", "aws-akid"}:
                severity = "medium"
            else:
                severity = "low"
            findings.append(
                Finding(
                    id=f"strings.pattern.{ident}",
                    title=title,
                    summary=summary,
                    category="indicator",
                    severity=severity,
                    confidence="medium",
                    analyzer=self.name,
                    tags=["string-pattern", ident],
                    evidence=[
                        Evidence(
                            kind="string",
                            summary=f"Matched {ident}",
                            analyzer=self.name,
                            location=f"offset {hit['offset']}",
                            value=hit["value"],
                            extra={"pattern": regex.pattern},
                        )
                        for hit in hits[:8]
                    ],
                )
            )

        return self.result(
            details={
                "ascii_count": ascii_count,
                "utf16le_count": utf16_count,
                "stored_count": len(stored),
                "strings": stored,
                "urls": urls,
                "domains": domains,
                "ips": ips,
                "emails": emails,
                "paths": paths[:MAX_INDICATORS],
                "registry": registry,
                "pattern_hit_counts": {key: len(value) for key, value in pattern_hits.items()},
            },
            findings=findings,
        )
