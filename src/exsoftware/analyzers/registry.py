"""Declarative analyzer registry for the trusted parent.

This module must not import analyzer implementation modules. The parent reads
eligibility metadata from AnalyzerSpec entries only. Workers load
implementations by worker_module / worker_class when they execute.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class AnalyzerSpec:
    """Trusted-parent metadata for one analyzer.

    ``worker_module`` / ``worker_class`` identify the implementation imported
    only inside an isolated worker (or explicit in-process test mode).
    """

    name: str
    version: str
    title: str
    worker_module: str
    worker_class: str
    detected_types: frozenset[str] | None = None
    detected_families: frozenset[str] | None = None
    timeout_seconds: float | None = None


# Order matches the historical ANALYZERS list (report readability, not correctness).
ANALYZER_REGISTRY: tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec(
        name="identity",
        version="1.0.0",
        title="File identity",
        worker_module="exsoftware.analyzers.identity",
        worker_class="IdentityAnalyzer",
    ),
    AnalyzerSpec(
        name="filesystem",
        version="1.0.0",
        title="Filesystem metadata",
        worker_module="exsoftware.analyzers.filesystem",
        worker_class="FilesystemAnalyzer",
    ),
    AnalyzerSpec(
        name="hashes",
        version="1.0.0",
        title="Hashes",
        worker_module="exsoftware.analyzers.hashes",
        worker_class="HashAnalyzer",
    ),
    AnalyzerSpec(
        name="entropy",
        version="1.0.0",
        title="Entropy",
        worker_module="exsoftware.analyzers.entropy",
        worker_class="EntropyAnalyzer",
    ),
    AnalyzerSpec(
        name="strings",
        version="1.0.0",
        title="Strings and indicators",
        worker_module="exsoftware.analyzers.strings",
        worker_class="StringsAnalyzer",
    ),
    AnalyzerSpec(
        name="pe",
        version="1.0.0",
        title="Windows PE",
        worker_module="exsoftware.analyzers.pe",
        worker_class="PEAnalyzer",
        detected_types=frozenset({"pe", "dos-mz"}),
    ),
    AnalyzerSpec(
        name="elf",
        version="1.0.0",
        title="ELF",
        worker_module="exsoftware.analyzers.elf",
        worker_class="ELFAnalyzer",
        detected_types=frozenset({"elf"}),
    ),
    AnalyzerSpec(
        name="macho",
        version="1.0.0",
        title="Mach-O",
        worker_module="exsoftware.analyzers.macho",
        worker_class="MachOAnalyzer",
        detected_types=frozenset({"macho32", "macho64", "macho-fat", "macho32-be", "macho64-be"}),
    ),
    AnalyzerSpec(
        name="lnk",
        version="1.0.0",
        title="Windows shortcut",
        worker_module="exsoftware.analyzers.lnk",
        worker_class="LnkAnalyzer",
        detected_types=frozenset({"lnk"}),
    ),
    AnalyzerSpec(
        name="archive",
        version="1.0.0",
        title="Archive / container",
        worker_module="exsoftware.analyzers.archive",
        worker_class="ArchiveAnalyzer",
        detected_types=frozenset({"zip", "jar", "apk", "wheel", "docx", "xlsx", "pptx", "gzip", "tar"}),
    ),
    AnalyzerSpec(
        name="pdf",
        version="1.0.0",
        title="PDF",
        worker_module="exsoftware.analyzers.pdf",
        worker_class="PDFAnalyzer",
        detected_types=frozenset({"pdf"}),
    ),
    AnalyzerSpec(
        name="image",
        version="1.0.0",
        title="Image",
        worker_module="exsoftware.analyzers.image",
        worker_class="ImageAnalyzer",
        detected_types=frozenset({"png", "jpeg", "gif", "bmp", "webp", "ico"}),
    ),
    AnalyzerSpec(
        name="ole",
        version="1.0.0",
        title="OLE / Office compound file",
        worker_module="exsoftware.analyzers.ole",
        worker_class="OLEAnalyzer",
        detected_types=frozenset({"ole", "doc", "xls", "ppt", "msi", "msg"}),
    ),
    AnalyzerSpec(
        name="script",
        version="1.0.0",
        title="Script / source",
        worker_module="exsoftware.analyzers.script",
        worker_class="ScriptAnalyzer",
        detected_types=frozenset(
            {
                "script",
                "python",
                "powershell",
                "javascript",
                "typescript",
                "vbscript",
                "batch",
                "shell",
                "ruby",
                "php",
                "text",
                "json",
                "html",
                "xml",
                "registry-script",
            }
        ),
        detected_families=frozenset({"script", "text"}),
    ),
    AnalyzerSpec(
        name="signature",
        version="1.0.0",
        title="Digital signature",
        worker_module="exsoftware.analyzers.signature",
        worker_class="SignatureAnalyzer",
        detected_types=frozenset({"pe", "msi"}),
    ),
    AnalyzerSpec(
        name="embedded",
        version="1.0.0",
        title="Embedded files",
        worker_module="exsoftware.analyzers.embedded",
        worker_class="EmbeddedAnalyzer",
    ),
)

_REGISTRY_BY_ID: dict[str, AnalyzerSpec] = {spec.name: spec for spec in ANALYZER_REGISTRY}
_EXTRA: list[AnalyzerSpec] = []


def all_specs() -> tuple[AnalyzerSpec, ...]:
    if not _EXTRA:
        return ANALYZER_REGISTRY
    return ANALYZER_REGISTRY + tuple(_EXTRA)


def get_spec(name: str) -> AnalyzerSpec | None:
    for spec in _EXTRA:
        if spec.name == name:
            return spec
    return _REGISTRY_BY_ID.get(name)


def register_spec(spec: AnalyzerSpec) -> AnalyzerSpec:
    """Add a declarative analyzer entry without importing its implementation."""
    if get_spec(spec.name) is not None:
        raise ValueError(f"analyzer {spec.name!r} is already registered")
    _EXTRA.append(spec)
    return spec


def iter_specs() -> Iterable[AnalyzerSpec]:
    yield from all_specs()
