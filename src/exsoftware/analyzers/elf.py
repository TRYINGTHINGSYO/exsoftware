from __future__ import annotations

import io

from ..models import Evidence, Finding
from ..rules.elf_capabilities import normalize_elf_library_name, normalize_elf_symbol_name
from .base import Analyzer

_IMPORTED_FUNCTION_CAP = 1000
_SYMBOL_SAMPLE_CAP = 200
_SYMBOL_SCAN_CAP = 400


def _decode_bytes(raw) -> str:
    if isinstance(raw, bytes):
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return str(raw)


def collect_imported_functions(elf) -> list[dict]:
    """Return undefined dynamic symbols with optional GNU-version library binding."""
    library_by_index = _gnu_version_libraries(elf)
    imported: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for section in elf.iter_sections():
        if getattr(section, "iter_symbols", None) is None or section.name != ".dynsym":
            continue
        for index, symbol in enumerate(section.iter_symbols()):
            name = symbol.name
            if not name:
                continue
            try:
                shndx = symbol["st_shndx"]
            except (KeyError, TypeError):
                continue
            if shndx not in {"SHN_UNDEF", 0}:
                continue
            try:
                symbol_type = symbol["st_info"]["type"]
            except (KeyError, TypeError):
                symbol_type = ""
            if symbol_type not in {"STT_FUNC", "STT_NOTYPE", "STT_GNU_IFUNC"}:
                continue
            normalized_name = normalize_elf_symbol_name(name)
            if not normalized_name:
                continue
            bound = library_by_index.get(index)
            library = bound[0] if bound else "unknown"
            version = bound[1] if bound else None
            normalized_library = normalize_elf_library_name(library)
            key = (normalized_library, normalized_name)
            if key in seen:
                continue
            seen.add(key)
            imported.append(
                {
                    "name": name,
                    "normalized_name": normalized_name,
                    "library": library,
                    "normalized_library": normalized_library,
                    "version": version,
                    "symbol_type": symbol_type,
                }
            )
            if len(imported) >= _IMPORTED_FUNCTION_CAP:
                return imported
    return imported


def _gnu_version_libraries(elf) -> dict[int, tuple[str, str | None]]:
    """Map .dynsym index -> (DT_NEEDED file, version name) via GNU versioning."""
    mapping: dict[int, tuple[str, str | None]] = {}
    try:
        versym = elf.get_section_by_name(".gnu.version")
        verneed = elf.get_section_by_name(".gnu.version_r")
    except Exception:
        return mapping
    if versym is None or verneed is None:
        return mapping
    if not hasattr(versym, "iter_symbols") or not hasattr(verneed, "iter_versions"):
        return mapping
    index_to_file: dict[int, tuple[str, str | None]] = {}
    try:
        for verneed_info, verdaux_iter in verneed.iter_versions():
            filename = getattr(verneed_info, "name", None) or ""
            if not filename:
                continue
            for aux in verdaux_iter:
                try:
                    other = int(aux["vna_other"])
                except (KeyError, TypeError, ValueError):
                    continue
                version = getattr(aux, "name", None)
                index_to_file[other] = (str(filename), str(version) if version else None)
    except Exception:
        return {}
    try:
        for index, ver in enumerate(versym.iter_symbols()):
            try:
                ndx = ver["ndx"]
            except (KeyError, TypeError):
                continue
            if ndx is None or isinstance(ndx, str):
                continue
            try:
                ndx_int = int(ndx) & 0x7FFF
            except (TypeError, ValueError):
                continue
            bound = index_to_file.get(ndx_int)
            if bound:
                mapping[index] = bound
    except Exception:
        return {}
    return mapping


class ELFAnalyzer(Analyzer):
    name = "elf"
    title = "ELF"
    detected_types = frozenset({"elf"})

    def analyze(self, ctx):
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection, DynamicSegment
            from elftools.elf.descriptions import describe_e_type, describe_e_machine
        except ImportError as exc:
            return self.failure(exc)

        stream = io.BytesIO(ctx.data)
        elf = ELFFile(stream)
        header = elf.header
        needed = []
        interpreter = None
        soname = None
        for section in elf.iter_sections():
            if section.name == ".interp":
                interpreter = _decode_bytes(section.data().split(b"\x00", 1)[0])
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif tag.entry.d_tag == "DT_SONAME":
                        soname = tag.soname
        if not needed:
            for segment in elf.iter_segments():
                if isinstance(segment, DynamicSegment):
                    for tag in segment.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)

        imported_functions = collect_imported_functions(elf)

        sections = []
        for section in elf.iter_sections():
            sections.append(
                {
                    "name": section.name,
                    "type": str(section["sh_type"]),
                    "size": int(section["sh_size"]),
                    "address": hex(int(section["sh_addr"])),
                }
            )

        symbols = []
        for section in elf.iter_sections():
            if getattr(section, "iter_symbols", None) and section.name in {".dynsym", ".symtab"}:
                for symbol in section.iter_symbols():
                    name = symbol.name
                    if name:
                        symbols.append(name)
                if len(symbols) > _SYMBOL_SCAN_CAP:
                    break

        findings = [
            Finding(
                id="elf.identity",
                title=f"ELF {header['e_ident']['EI_CLASS']} {describe_e_machine(header['e_machine'])}",
                summary=(
                    f"This is an ELF {describe_e_type(header['e_type'])} for "
                    f"{describe_e_machine(header['e_machine'])} with {len(needed)} DT_NEEDED libraries."
                ),
                category="executable",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["elf"],
                evidence=[
                    Evidence(kind="field", summary="Type", analyzer=self.name, value=str(describe_e_type(header["e_type"]))),
                    Evidence(kind="field", summary="Machine", analyzer=self.name, value=str(describe_e_machine(header["e_machine"]))),
                    Evidence(kind="field", summary="Entry", analyzer=self.name, value=hex(header["e_entry"])),
                ],
            )
        ]
        if needed:
            findings.append(
                Finding(
                    id="elf.needed",
                    title="Shared library dependencies",
                    summary="DT_NEEDED entries list libraries this binary expects at runtime.",
                    category="dependencies",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["dependencies"],
                    evidence=[
                        Evidence(kind="field", summary="DT_NEEDED", analyzer=self.name, value=name)
                        for name in needed[:20]
                    ],
                )
            )
        if interpreter:
            findings.append(
                Finding(
                    id="elf.interpreter",
                    title="Dynamic interpreter",
                    summary="The PT_INTERP / .interp path is the runtime loader.",
                    category="dependencies",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["interpreter"],
                    evidence=[
                        Evidence(kind="string", summary=".interp", analyzer=self.name, value=interpreter)
                    ],
                )
            )

        details = {
            "class": header["e_ident"]["EI_CLASS"],
            "data": header["e_ident"]["EI_DATA"],
            "osabi": header["e_ident"]["EI_OSABI"],
            "type": str(describe_e_type(header["e_type"])),
            "machine": str(describe_e_machine(header["e_machine"])),
            "entry": hex(header["e_entry"]),
            "interpreter": interpreter,
            "soname": soname,
            "needed": needed,
            "needed_normalized": [normalize_elf_library_name(name) for name in needed],
            "imported_functions": imported_functions,
            "sections": sections[:80],
            "symbols_sample": symbols[:_SYMBOL_SAMPLE_CAP],
            "symbol_count": len(symbols),
        }
        return self.result(details=details, findings=findings)
