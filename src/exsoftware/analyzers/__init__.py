from .archive import ArchiveAnalyzer
from .base import Analyzer
from .eligibility import class_spec, is_eligible, skip_reason_for
from .elf import ELFAnalyzer
from .embedded import EmbeddedAnalyzer
from .entropy import EntropyAnalyzer
from .filesystem import FilesystemAnalyzer
from .hashes import HashAnalyzer
from .identity import IdentityAnalyzer
from .image import ImageAnalyzer
from .lnk import LnkAnalyzer
from .macho import MachOAnalyzer
from .ole import OLEAnalyzer
from .pdf import PDFAnalyzer
from .pe import PEAnalyzer
from .script import ScriptAnalyzer
from .signature import SignatureAnalyzer
from .strings import StringsAnalyzer

# Order matters for readability in the report, not for correctness.
ANALYZERS: list[type[Analyzer]] = [
    IdentityAnalyzer,
    FilesystemAnalyzer,
    HashAnalyzer,
    EntropyAnalyzer,
    StringsAnalyzer,
    PEAnalyzer,
    ELFAnalyzer,
    MachOAnalyzer,
    LnkAnalyzer,
    ArchiveAnalyzer,
    PDFAnalyzer,
    ImageAnalyzer,
    OLEAnalyzer,
    ScriptAnalyzer,
    SignatureAnalyzer,
    EmbeddedAnalyzer,
]


def register(analyzer_cls: type[Analyzer]) -> type[Analyzer]:
    """Add an analyzer without rewriting the pipeline."""
    ANALYZERS.append(analyzer_cls)
    return analyzer_cls


def get_analyzer_class(name: str) -> type[Analyzer] | None:
    for cls in ANALYZERS:
        if cls.name == name:
            return cls
    return None


__all__ = [
    "ANALYZERS",
    "Analyzer",
    "class_spec",
    "get_analyzer_class",
    "is_eligible",
    "register",
    "skip_reason_for",
]
