from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Evidence, Finding
from ..rules.pe_capabilities import normalize_dll_name, normalize_windows_api_name
from ..rules.indicators import INTERESTING_APIS, INJECTION_SET, NETWORK_SET, PACKER_SECTION_NAMES
from .base import Analyzer
from .entropy import shannon_entropy

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc

_PE_TYPES = {"pe", "dos-mz"}

_MACHINE = {
    0x14C: "I386",
    0x8664: "AMD64",
    0x1C0: "ARM",
    0xAA64: "ARM64",
    0x1C4: "ARMNT",
    0x200: "IA64",
}

_SUBSYSTEM = {
    1: "native",
    2: "windows-gui",
    3: "windows-console",
    5: "os2-cui",
    7: "posix-cui",
    9: "windows-ce-gui",
    10: "efi-application",
    11: "efi-boot-service-driver",
    12: "efi-runtime-driver",
    13: "efi-rom",
    14: "xbox",
    16: "windows-boot-application",
}


def _ts(value: int) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _decode_name(raw) -> str:
    if isinstance(raw, bytes):
        return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
    return str(raw)


def _as_int(value, default: int = 0) -> int:
    if value is None:
        return default
    if hasattr(value, "value"):
        try:
            return int(value.value)
        except (TypeError, ValueError):
            pass
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _hex(value) -> str:
    return hex(_as_int(value))


_EXECUTION_LEVEL_RE = re.compile(r"requestedExecutionLevel\b[^>]*\blevel\s*=\s*['\"]([^'\"]+)['\"]", re.I)


def _entry_point_section(sections: list[dict], entry_rva: int) -> dict | None:
    if not entry_rva:
        return None
    for section in sections:
        start = int(section.get("virtual_address_rva") or 0)
        size = max(int(section.get("virtual_size") or 0), int(section.get("raw_size") or 0))
        if start <= entry_rva < start + size:
            return {
                "name": section.get("name"),
                "virtual_address": section.get("virtual_address"),
                "executable": bool(section.get("executable")),
                "writable": bool(section.get("writable")),
                "readable": bool(section.get("readable")),
                "entropy": section.get("entropy"),
            }
    return None


class PEAnalyzer(Analyzer):
    name = "pe"
    title = "Windows PE"
    detected_types = frozenset(_PE_TYPES)

    def analyze(self, ctx):
        try:
            import pefile
        except ImportError as exc:
            return self.failure(exc)

        if ctx.identity and ctx.identity.detected_type == "dos-mz":
            return self.result(
                details={"note": "MZ header present but PE signature was not found."},
                findings=[
                    Finding(
                        id="pe.mz-only",
                        title="DOS MZ file without a PE signature",
                        summary="The file starts with MZ but does not contain PE\\0\\0 at e_lfanew.",
                        category="executable",
                        severity="low",
                        confidence="high",
                        analyzer=self.name,
                        tags=["pe"],
                        evidence=[
                            Evidence(
                                kind="bytes",
                                summary="Leading magic",
                                analyzer=self.name,
                                location="offset 0",
                                value=ctx.data[:2].hex(),
                            )
                        ],
                    )
                ],
            )

        pe = pefile.PE(data=ctx.data, fast_load=False)
        try:
            return self._analyze_pe(pe, ctx)
        finally:
            pe.close()

    def _analyze_pe(self, pe, ctx):
        fh = pe.FILE_HEADER
        oh = pe.OPTIONAL_HEADER
        machine_id = _as_int(fh.Machine)
        machine = _MACHINE.get(machine_id, _hex(machine_id))
        characteristics = _as_int(fh.Characteristics)
        is_dll = bool(characteristics & 0x2000)
        is_exe = bool(characteristics & 0x0002)
        subsystem_id = _as_int(getattr(oh, "Subsystem", 0))
        subsystem = _SUBSYSTEM.get(subsystem_id, str(subsystem_id))
        magic = _as_int(getattr(oh, "Magic", 0))
        pe_format = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else _hex(magic)
        timestamp = _as_int(fh.TimeDateStamp)
        image_base = _as_int(getattr(oh, "ImageBase", 0))
        entry_rva = _as_int(getattr(oh, "AddressOfEntryPoint", 0))

        sections = []
        wx_sections = []
        packer_sections = []
        for section in pe.sections:
            name = _decode_name(section.Name)
            raw_size = _as_int(section.SizeOfRawData)
            virt_size = _as_int(section.Misc_VirtualSize)
            chars = _as_int(section.Characteristics)
            data = section.get_data()
            entropy = shannon_entropy(data[: min(len(data), 1024 * 1024)]) if data else 0.0
            executable = bool(chars & 0x20000000)
            writable = bool(chars & 0x80000000)
            readable = bool(chars & 0x40000000)
            info = {
                "name": name,
                "virtual_address": _hex(section.VirtualAddress),
                "virtual_address_rva": _as_int(section.VirtualAddress),
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "entropy": round(entropy, 4),
                "executable": executable,
                "writable": writable,
                "readable": readable,
                "characteristics": _hex(chars),
            }
            sections.append(info)
            if executable and writable:
                wx_sections.append(info)
            if name in PACKER_SECTION_NAMES or name.upper() in PACKER_SECTION_NAMES:
                packer_sections.append(name)

        imports: list[dict] = []
        imported_functions: list[dict] = []
        interesting_imports: list[dict] = []
        delayed = []
        delayed_imports: list[dict] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = _decode_name(import_entry.dll) if import_entry.dll else "unknown"
                normalized_dll = normalize_dll_name(dll)
                functions = []
                for imp in import_entry.imports:
                    ordinal = None
                    if imp.name:
                        fname = _decode_name(imp.name)
                    elif imp.ordinal:
                        ordinal = _as_int(imp.ordinal)
                        fname = f"#{imp.ordinal}"
                    else:
                        fname = "unknown"
                    normalized_name = normalize_windows_api_name(fname)
                    functions.append(fname)
                    imported_functions.append(
                        {
                            "dll": dll,
                            "normalized_dll": normalized_dll,
                            "name": fname,
                            "normalized_name": normalized_name,
                            "import_kind": "ordinal" if ordinal is not None else "name",
                            "ordinal": ordinal,
                        }
                    )
                    note = INTERESTING_APIS.get(fname) or (
                        INTERESTING_APIS.get(normalized_name) if normalized_name else None
                    )
                    if note:
                        interesting_imports.append(
                            {
                                "dll": dll,
                                "normalized_dll": normalized_dll,
                                "name": fname,
                                "normalized_name": normalized_name,
                                "note": note,
                            }
                        )
                imports.append(
                    {
                        "dll": dll,
                        "normalized_dll": normalized_dll,
                        "count": len(functions),
                        "functions": functions,
                    }
                )
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for delay_entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll = _decode_name(delay_entry.dll) if delay_entry.dll else "unknown"
                delayed.append(dll)
                delayed_imports.append({"dll": dll, "normalized_dll": normalize_dll_name(dll)})

        exports = []
        export_features = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:400]:
                name = _decode_name(exp.name) if exp.name else f"#{exp.ordinal}"
                exports.append(name)
                export_features.append(
                    {
                        "name": name,
                        "normalized_name": normalize_windows_api_name(name),
                        "ordinal": _as_int(getattr(exp, "ordinal", None), 0),
                    }
                )

        resources = []
        version_info = {}
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for etype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = pefile_type_name(etype)
                count = 0
                if etype.directory:
                    for ident in etype.directory.entries:
                        if ident.directory:
                            count += len(ident.directory.entries)
                        else:
                            count += 1
                resources.append({"type": type_name, "count": max(count, 1)})
        manifest = _manifest_info(pe)
        try:
            for fileinfo in getattr(pe, "FileInfo", []) or []:
                for info in fileinfo:
                    if hasattr(info, "StringTable"):
                        for table in info.StringTable:
                            for key, value in table.entries.items():
                                version_info[_decode_name(key)] = _decode_name(value)
        except Exception:
            pass

        pdb_paths = []
        debug_types = []
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for debug in pe.DIRECTORY_ENTRY_DEBUG:
                debug_types.append(_as_int(debug.struct.Type))
                debug_entry = getattr(debug, "entry", None)
                if debug_entry is not None and hasattr(debug_entry, "PdbFileName"):
                    pdb_paths.append(_decode_name(debug_entry.PdbFileName))

        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 else None
        is_dotnet = bool(clr_dir and _as_int(clr_dir.VirtualAddress) and _as_int(clr_dir.Size))

        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_size = 0
        if overlay_offset:
            overlay_offset = _as_int(overlay_offset)
            overlay_size = max(0, len(ctx.data) - overlay_offset)

        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
        signed_blob = bool(security and _as_int(security.VirtualAddress) and _as_int(security.Size))

        tls_callbacks = 0
        tls_callback_address = 0
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
            tls = pe.DIRECTORY_ENTRY_TLS.struct
            addr = _as_int(getattr(tls, "AddressOfCallBacks", 0))
            tls_callback_address = addr
            tls_callbacks = 1 if addr else 0

        imphash = None
        try:
            imphash = pe.get_imphash()
        except Exception:
            pass

        findings: list[Finding] = []
        kind = "DLL" if is_dll else "driver" if subsystem == "native" else "EXE"
        findings.append(
            Finding(
                id="pe.identity",
                title=f"{pe_format} {kind} for {machine}",
                summary=(
                    f"This is a {pe_format} {kind} targeting {machine}, subsystem {subsystem}, "
                    f"with {len(sections)} section(s) and {sum(item['count'] for item in imports)} import(s) "
                    f"from {len(imports)} DLL(s)."
                ),
                category="executable",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["pe"],
                evidence=[
                    Evidence(kind="field", summary="PE format", analyzer=self.name, value=pe_format),
                    Evidence(kind="field", summary="Machine", analyzer=self.name, value=str(machine)),
                    Evidence(kind="field", summary="Subsystem", analyzer=self.name, value=subsystem),
                    Evidence(kind="field", summary="Timestamp", analyzer=self.name, value=_ts(timestamp) or str(timestamp)),
                ],
            )
        )

        if is_dotnet:
            findings.append(
                Finding(
                    id="pe.dotnet",
                    title=".NET assembly",
                    summary="The CLR runtime header is present, so this is a .NET binary.",
                    category="executable",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["dotnet"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary="COM descriptor directory",
                            analyzer=self.name,
                            value=f"VA={_hex(clr_dir.VirtualAddress)} size={_as_int(clr_dir.Size)}",
                        )
                    ],
                )
            )

        if wx_sections:
            findings.append(
                Finding(
                    id="pe.wx-section",
                    title="Writable and executable section",
                    summary=(
                        "One or more sections are marked both writable and executable. "
                        "That can be legitimate, but it is also common in packed or self-modifying code."
                    ),
                    category="packing",
                    severity="medium",
                    confidence="high",
                    analyzer=self.name,
                    tags=["wx", "memory"],
                    evidence=[
                        Evidence(
                            kind="structure",
                            summary=f"Section {item['name']} is W+X",
                            analyzer=self.name,
                            location=item["virtual_address"],
                            value=str(item),
                        )
                        for item in wx_sections
                    ],
                )
            )

        if packer_sections:
            findings.append(
                Finding(
                    id="pe.packer-section-name",
                    title="Section name associated with packing tools",
                    summary=(
                        "A section name matches a known packer/protector family. "
                        "Names can be spoofed; this is a clue, not a conclusion."
                    ),
                    category="packing",
                    severity="medium",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["packer"],
                    evidence=[
                        Evidence(kind="field", summary="Section name", analyzer=self.name, value=name)
                        for name in packer_sections
                    ],
                )
            )

        high_entropy_exec = [item for item in sections if item["executable"] and item["entropy"] >= 7.2]
        if high_entropy_exec:
            findings.append(
                Finding(
                    id="pe.high-entropy-code",
                    title="Executable section with high entropy",
                    summary="An executable section looks compressed or encrypted.",
                    category="packing",
                    severity="medium",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["entropy", "packer"],
                    evidence=[
                        Evidence(
                            kind="metric",
                            summary=f"{item['name']} entropy {item['entropy']}",
                            analyzer=self.name,
                            location=item["virtual_address"],
                            value=str(item["entropy"]),
                        )
                        for item in high_entropy_exec
                    ],
                )
            )

        import_names = {
            str(value)
            for item in imported_functions
            for value in (item.get("name"), item.get("normalized_name"))
            if value
        }
        if len(imports) <= 2 and not is_dotnet and ctx.size > 20_000:
            findings.append(
                Finding(
                    id="pe.few-imports",
                    title="Very small import table",
                    summary=(
                        f"Only {len(imports)} imported DLL(s) were found. Packers and some native "
                        "stubs resolve most APIs at runtime."
                    ),
                    category="packing",
                    severity="low",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["imports", "packer"],
                    evidence=[
                        Evidence(
                            kind="count",
                            summary="Imported DLL count",
                            analyzer=self.name,
                            value=str(len(imports)),
                        )
                    ],
                )
            )

        if interesting_imports:
            findings.append(
                Finding(
                    id="pe.interesting-imports",
                    title="Imports that often matter during review",
                    summary=(
                        "These APIs are commonly involved in process control, memory, networking, "
                        "persistence, or inspection. Presence is not a verdict."
                    ),
                    category="executable",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["imports", "capabilities"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary=f"{item['dll']}!{item['name']}",
                            analyzer=self.name,
                            location=f"import {item['dll']}",
                            value=item["note"],
                        )
                        for item in interesting_imports[:20]
                    ],
                )
            )

        injection_hits = sorted(import_names & INJECTION_SET)
        if len(injection_hits) >= 2:
            findings.append(
                Finding(
                    id="pe.injection-import-set",
                    title="Import set often used to run code in another process",
                    summary=(
                        "This binary imports multiple APIs that together are frequently used "
                        "to allocate, write, and execute memory in another process."
                    ),
                    category="executable",
                    severity="medium",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["injection", "capabilities"],
                    evidence=[
                        Evidence(kind="field", summary="Imported API", analyzer=self.name, value=name)
                        for name in injection_hits
                    ],
                )
            )

        if overlay_size:
            findings.append(
                Finding(
                    id="pe.overlay",
                    title="Overlay data after the PE image",
                    summary=(
                        f"{overlay_size} byte(s) sit after the PE image. Installers, packed files, "
                        "and appended payloads often use an overlay."
                    ),
                    category="embedded",
                    severity="low",
                    confidence="high",
                    analyzer=self.name,
                    tags=["overlay"],
                    evidence=[
                        Evidence(
                            kind="structure",
                            summary="Overlay start and size",
                            analyzer=self.name,
                            location=f"offset {overlay_offset}",
                            value=str(overlay_size),
                        )
                    ],
                )
            )

        if pdb_paths:
            findings.append(
                Finding(
                    id="pe.pdb-path",
                    title="Debug PDB path present",
                    summary="A PDB path can reveal the original project name and build machine layout.",
                    category="metadata",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["pdb", "build"],
                    evidence=[
                        Evidence(kind="string", summary="PDB path", analyzer=self.name, value=path)
                        for path in pdb_paths
                    ],
                )
            )

        if version_info:
            findings.append(
                Finding(
                    id="pe.version-info",
                    title="Version resource present",
                    summary="The PE version resource contains descriptive metadata.",
                    category="metadata",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["version"],
                    evidence=[
                        Evidence(kind="field", summary=key, analyzer=self.name, value=str(value)[:300])
                        for key, value in list(version_info.items())[:12]
                    ],
                )
            )

        if signed_blob:
            findings.append(
                Finding(
                    id="pe.authenticode-blob",
                    title="Authenticode certificate table is present",
                    summary="The PE security data directory is populated. See the signature analyzer for parsed details.",
                    category="signature",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["signature"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary="IMAGE_DIRECTORY_ENTRY_SECURITY",
                            analyzer=self.name,
                            location=f"file offset {_as_int(security.VirtualAddress)}",
                            value=f"size={_as_int(security.Size)}",
                        )
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    id="pe.unsigned",
                    title="No Authenticode certificate table",
                    summary="The PE security directory is empty. This file may still be catalog-signed on Windows; that is not checked here.",
                    category="signature",
                    severity="info",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["signature"],
                    evidence=[
                        Evidence(
                            kind="field",
                            summary="Empty security directory",
                            analyzer=self.name,
                            value="VA=0 size=0",
                        )
                    ],
                )
            )

        capabilities = []
        if import_names & NETWORK_SET:
            capabilities.append("network")
        if import_names & {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"}:
            capabilities.append("registry-write")
        if import_names & {"CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW"}:
            capabilities.append("start-process")
        if injection_hits:
            capabilities.append("cross-process-memory")
        if import_names & {"CreateServiceA", "CreateServiceW"}:
            capabilities.append("install-service")
        if import_names & {"GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW"}:
            capabilities.append("observe-input")
        if import_names & {"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt"}:
            capabilities.append("crypto")

        details = {
            "format": pe_format,
            "machine": machine,
            "is_dll": is_dll,
            "is_exe": is_exe,
            "is_dotnet": is_dotnet,
            "subsystem": subsystem,
            "timestamp": timestamp,
            "timestamp_iso": _ts(timestamp),
            "image_base": _hex(image_base),
            "entry_point_rva": _hex(entry_rva),
            "entry_point_section": _entry_point_section(sections, entry_rva),
            "section_count": len(sections),
            "sections": sections,
            "rwx_sections": wx_sections,
            "high_entropy_executable_sections": high_entropy_exec,
            "packer_section_names": packer_sections,
            "imports": imports,
            "imported_functions": imported_functions,
            "delayed_imports": delayed,
            "delayed_import_features": delayed_imports,
            "interesting_imports": interesting_imports,
            "exports": exports[:200],
            "exported_functions": export_features[:200],
            "export_count": len(exports),
            "resources": resources,
            "manifest": manifest,
            "version_info": version_info,
            "pdb_paths": pdb_paths,
            "debug_types": debug_types,
            "debug_directory_present": bool(debug_types),
            "overlay_offset": overlay_offset,
            "overlay_size": overlay_size,
            "authenticode_directory": {
                "offset": _as_int(security.VirtualAddress) if security else 0,
                "size": _as_int(security.Size) if security else 0,
            },
            "tls_callbacks_present": bool(tls_callbacks),
            "tls_callback_count": tls_callbacks,
            "tls_callback_address": _hex(tls_callback_address),
            "imphash": imphash,
            "capabilities": capabilities,
        }
        return self.result(details=details, findings=findings)


def _manifest_info(pe) -> dict:
    info = {"present": False, "requested_execution_level": None}
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return info
    try:
        for etype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = pefile_type_name(etype)
            if type_name != "MANIFEST" and _as_int(getattr(etype, "id", None), 0) != 24:
                continue
            for data_entry in _resource_data_entries(etype):
                data = pe.get_data(
                    _as_int(data_entry.OffsetToData),
                    min(_as_int(data_entry.Size), 64 * 1024),
                )
                text = _decode_manifest(data)
                match = _EXECUTION_LEVEL_RE.search(text)
                info["present"] = True
                if match:
                    info["requested_execution_level"] = match.group(1)
                    return info
    except Exception:
        return info
    return info


def _resource_data_entries(entry) -> list:
    out = []
    directory = getattr(entry, "directory", None)
    if not directory:
        data = getattr(entry, "data", None)
        struct = getattr(data, "struct", None)
        return [struct] if struct is not None else []
    for child in getattr(directory, "entries", []) or []:
        out.extend(_resource_data_entries(child))
    return out


def _decode_manifest(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            return data.decode(encoding, "ignore")
        except Exception:
            continue
    return ""


def pefile_type_name(entry) -> str:
    if entry.name:
        return _decode_name(entry.name)
    mapping = {
        1: "CURSOR",
        2: "BITMAP",
        3: "ICON",
        4: "MENU",
        5: "DIALOG",
        6: "STRING",
        7: "FONTDIR",
        8: "FONT",
        9: "ACCELERATOR",
        10: "RCDATA",
        11: "MESSAGETABLE",
        12: "GROUP_CURSOR",
        14: "GROUP_ICON",
        16: "VERSION",
        24: "MANIFEST",
    }
    return mapping.get(_as_int(entry.id), str(entry.id))
