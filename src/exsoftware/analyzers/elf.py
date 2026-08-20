from __future__ import annotations

import io

from ..models import Evidence, Finding
from .base import Analyzer


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
                interpreter = section.data().split(b"\x00", 1)[0].decode("utf-8", "replace")
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
                if len(symbols) > 400:
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
            "sections": sections[:80],
            "symbols_sample": symbols[:200],
            "symbol_count": len(symbols),
        }
        return self.result(details=details, findings=findings)
