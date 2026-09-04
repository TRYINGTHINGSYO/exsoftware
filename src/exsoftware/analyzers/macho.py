from __future__ import annotations

import struct

from ..models import Evidence, Finding
from ..rules.macho_capabilities import normalize_macho_library_name, normalize_macho_symbol_name
from .base import Analyzer

_MACHO_TYPES = {"macho32", "macho64", "macho-fat", "macho32-be", "macho64-be"}

_FILETYPES = {
    1: "OBJECT",
    2: "EXECUTE",
    3: "FVMLIB",
    4: "CORE",
    5: "PRELOAD",
    6: "DYLIB",
    7: "DYLINKER",
    8: "BUNDLE",
    9: "DYLIB_STUB",
    10: "DSYM",
    11: "KEXT_BUNDLE",
}

LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x18
LC_RPATH = 0x1C | 0x80000000
LC_CODE_SIGNATURE = 0x1D
LC_REEXPORT_DYLIB = 0x1F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x23
LC_MAIN = 0x28 | 0x80000000

_DEPENDS_ON_DYLIB = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB}
_ORDINAL_DYLIB = {
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}

N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x00
SELF_LIBRARY_ORDINAL = 0
DYNAMIC_LOOKUP_ORDINAL = 0xFE
EXECUTABLE_ORDINAL = 0xFF

_IMPORTED_FUNCTION_CAP = 1000
_SYMBOL_SCAN_CAP = 20000


def collect_imported_functions(
    data: bytes,
    *,
    endian: str,
    is64: bool,
    ordinal_dylibs: list[str],
    symtab: tuple[int, int, int, int] | None,
    undef_range: tuple[int, int] | None = None,
) -> list[dict]:
    """Return undefined Mach-O symbols with two-level-namespace dylib binding when present."""
    if not symtab:
        return []
    symoff, nsyms, stroff, strsize = symtab
    if nsyms <= 0 or strsize < 0 or stroff < 0 or symoff < 0:
        return []
    entry_size = 16 if is64 else 12
    fmt = endian + ("IBBHQ" if is64 else "IBBHI")
    nsyms = min(int(nsyms), _SYMBOL_SCAN_CAP)
    if undef_range is not None:
        start, count = undef_range
        if start < 0 or count < 0:
            indexes = range(nsyms)
        else:
            indexes = range(max(0, start), min(nsyms, start + count))
    else:
        indexes = range(nsyms)

    imported: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for index in indexes:
        entry_off = symoff + index * entry_size
        if entry_off + entry_size > len(data):
            break
        try:
            n_strx, n_type, _n_sect, n_desc, _n_value = struct.unpack(fmt, data[entry_off : entry_off + entry_size])
        except struct.error:
            break
        if n_type & N_STAB:
            continue
        if (n_type & N_TYPE) != N_UNDF or not (n_type & N_EXT):
            continue
        name = _string_at(data, stroff, strsize, n_strx)
        if not name:
            continue
        normalized_name = normalize_macho_symbol_name(name)
        if not normalized_name:
            continue
        library = _library_for_ordinal(ordinal_dylibs, n_desc)
        normalized_library = normalize_macho_library_name(library)
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
            }
        )
        if len(imported) >= _IMPORTED_FUNCTION_CAP:
            break
    return imported


def _string_at(data: bytes, stroff: int, strsize: int, n_strx: int) -> str | None:
    if n_strx < 0 or strsize <= 0:
        return None
    start = stroff + n_strx
    end = stroff + strsize
    if start < 0 or start >= len(data) or start >= end:
        return None
    raw = data[start : min(end, start + 512, len(data))].split(b"\x00", 1)[0]
    if not raw:
        return None
    return raw.decode("utf-8", "replace")


def _library_for_ordinal(ordinal_dylibs: list[str], n_desc: int) -> str:
    ordinal = (int(n_desc) >> 8) & 0xFF
    if ordinal in {SELF_LIBRARY_ORDINAL, DYNAMIC_LOOKUP_ORDINAL, EXECUTABLE_ORDINAL}:
        return "unknown"
    index = ordinal - 1
    if 0 <= index < len(ordinal_dylibs):
        return ordinal_dylibs[index]
    return "unknown"


class MachOAnalyzer(Analyzer):
    name = "macho"
    title = "Mach-O"
    detected_types = frozenset(_MACHO_TYPES)

    def analyze(self, ctx):
        magic = ctx.data[:4]
        if magic == b"\xca\xfe\xba\xbe":
            return self._fat(ctx.data)
        return self._thin(ctx.data)

    def _fat(self, data: bytes):
        if len(data) < 8:
            return self.failure(ValueError("Truncated fat Mach-O header"))
        nfat = int.from_bytes(data[4:8], "big")
        arches = []
        offset = 8
        for _ in range(min(nfat, 16)):
            if offset + 20 > len(data):
                break
            cputype, subtype, off, size, align = struct.unpack(">IIIII", data[offset : offset + 20])
            arches.append(
                {
                    "cputype": cputype,
                    "cpusubtype": subtype,
                    "offset": off,
                    "size": size,
                    "align": align,
                }
            )
            offset += 20
        findings = [
            Finding(
                id="macho.fat",
                title=f"Fat Mach-O with {len(arches)} architecture(s)",
                summary="A universal binary contains multiple Mach-O slices.",
                category="executable",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["macho"],
                evidence=[
                    Evidence(kind="structure", summary="Fat arch", analyzer=self.name, value=str(item))
                    for item in arches[:8]
                ],
            )
        ]
        details = {"kind": "fat", "nfat": nfat, "arches": arches}
        if arches:
            slice_off = arches[0]["offset"]
            slice_end = slice_off + min(arches[0]["size"], max(0, len(data) - slice_off))
            if 0 <= slice_off < len(data):
                thin = self._thin(data[slice_off:slice_end], prefix="slice0.")
                details["first_slice"] = thin.details
                # Symbol features only. Do not lift dylibs: fat reports historically
                # omit top-level dylibs, and DEPENDS_ON must stay that way.
                details["imported_functions"] = list(thin.details.get("imported_functions") or [])
                findings.extend(thin.findings)
        return self.result(details=details, findings=findings)

    def _thin(self, data: bytes, prefix: str = ""):
        if len(data) < 32:
            return self.result(details={"error": "truncated"}, findings=[])
        magic = data[:4]
        little = magic in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
        is64 = magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}
        endian = "<" if little else ">"
        header_size = 32 if is64 else 28
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            endian + "IIIIII", data[4:28]
        )
        offset = header_size
        dylibs = []
        ordinal_dylibs = []
        rpaths = []
        signed = False
        ident = None
        symtab = None
        undef_range = None
        for _ in range(min(ncmds, 512)):
            if offset + 8 > len(data) or offset > header_size + sizeofcmds:
                break
            cmd, cmdsize = struct.unpack(endian + "II", data[offset : offset + 8])
            if cmdsize < 8 or offset + cmdsize > len(data):
                break
            body = data[offset : offset + cmdsize]
            plain = cmd & 0x7FFFFFFF
            if plain in {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB, *_ORDINAL_DYLIB} and cmdsize >= 24:
                name_off = struct.unpack(endian + "I", body[8:12])[0]
                raw = body[name_off:].split(b"\x00", 1)[0]
                name = raw.decode("utf-8", "replace")
                if plain == LC_ID_DYLIB:
                    ident = name
                else:
                    if plain in _DEPENDS_ON_DYLIB:
                        dylibs.append(name)
                    if plain in _ORDINAL_DYLIB:
                        ordinal_dylibs.append(name)
            elif cmd == LC_RPATH and cmdsize >= 12:
                name_off = struct.unpack(endian + "I", body[8:12])[0]
                rpaths.append(body[name_off:].split(b"\x00", 1)[0].decode("utf-8", "replace"))
            elif plain == LC_CODE_SIGNATURE:
                signed = True
            elif plain == LC_SYMTAB and cmdsize >= 24:
                symoff, nsyms, stroff, strsize = struct.unpack(endian + "IIII", body[8:24])
                symtab = (int(symoff), int(nsyms), int(stroff), int(strsize))
            elif plain == LC_DYSYMTAB and cmdsize >= 32:
                iundefsym, nundefsym = struct.unpack(endian + "II", body[24:32])
                undef_range = (int(iundefsym), int(nundefsym))
            offset += cmdsize

        imported_functions = collect_imported_functions(
            data,
            endian=endian,
            is64=is64,
            ordinal_dylibs=ordinal_dylibs,
            symtab=symtab,
            undef_range=undef_range,
        )

        findings = [
            Finding(
                id=f"{prefix}macho.identity" if prefix else "macho.identity",
                title=f"Mach-O { _FILETYPES.get(filetype, filetype) } ({'64' if is64 else '32'}-bit)",
                summary=(
                    f"Mach-O filetype {_FILETYPES.get(filetype, filetype)} with {len(dylibs)} linked "
                    f"dylib(s)."
                ),
                category="executable",
                severity="info",
                confidence="high",
                analyzer=self.name,
                tags=["macho"],
                evidence=[
                    Evidence(kind="field", summary="cputype", analyzer=self.name, value=str(cputype)),
                    Evidence(kind="field", summary="ncmds", analyzer=self.name, value=str(ncmds)),
                ],
            )
        ]
        if dylibs:
            findings.append(
                Finding(
                    id=f"{prefix}macho.dylibs" if prefix else "macho.dylibs",
                    title="Linked dylibs",
                    summary="Load commands name the libraries this binary links against.",
                    category="dependencies",
                    severity="info",
                    confidence="high",
                    analyzer=self.name,
                    tags=["dependencies"],
                    evidence=[
                        Evidence(kind="string", summary="LC_LOAD_DYLIB", analyzer=self.name, value=name)
                        for name in dylibs[:20]
                    ],
                )
            )
        if signed:
            findings.append(
                Finding(
                    id=f"{prefix}macho.code-signature" if prefix else "macho.code-signature",
                    title="LC_CODE_SIGNATURE present",
                    summary="A code signature load command exists. The signature blob is not fully validated in this milestone.",
                    category="signature",
                    severity="info",
                    confidence="medium",
                    analyzer=self.name,
                    tags=["signature"],
                    evidence=[
                        Evidence(kind="field", summary="LC_CODE_SIGNATURE", analyzer=self.name, value="present")
                    ],
                )
            )
        details = {
            "magic": magic.hex(),
            "is64": is64,
            "little_endian": little,
            "cputype": cputype,
            "cpusubtype": cpusubtype,
            "filetype": _FILETYPES.get(filetype, filetype),
            "ncmds": ncmds,
            "flags": flags,
            "id": ident,
            "dylibs": dylibs,
            "dylibs_normalized": [normalize_macho_library_name(name) for name in dylibs],
            "imported_functions": imported_functions,
            "rpaths": rpaths,
            "code_signature_command": signed,
        }
        return self.result(details=details, findings=findings)
