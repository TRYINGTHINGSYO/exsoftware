from __future__ import annotations

from datetime import datetime, timezone

from exsoftware.cli import render_text
from exsoftware.composition import compose
from exsoftware.content import content_id_from_digest
from exsoftware.investigation import Investigation
from exsoftware.models import AnalyzerResult, Evidence, FileIdentity, Finding, Report
from exsoftware.rules.pe_capabilities import normalize_dll_name, normalize_windows_api_name


SHA = "1" * 64


def _identity() -> FileIdentity:
    return FileIdentity(
        name="sample.exe",
        path=None,
        source="bytes",
        extension=".exe",
        size=1024,
        detected_type="pe",
        detected_family="executable",
        detected_mime="application/vnd.microsoft.portable-executable",
        description="Windows PE executable",
        extension_matches=True,
        magic_offset=0,
        magic_hex="4d5a",
    )


def _pe_details(imports: dict[str, list[str]]) -> dict:
    rows = []
    functions = []
    for dll, names in imports.items():
        normalized_dll = normalize_dll_name(dll)
        rows.append({"dll": dll, "normalized_dll": normalized_dll, "count": len(names), "functions": list(names)})
        for name in names:
            ordinal = int(name[1:]) if name.startswith("#") and name[1:].isdigit() else None
            functions.append(
                {
                    "dll": dll,
                    "normalized_dll": normalized_dll,
                    "name": name,
                    "normalized_name": normalize_windows_api_name(name),
                    "import_kind": "ordinal" if ordinal is not None else "name",
                    "ordinal": ordinal,
                }
            )
    return {
        "format": "PE32+",
        "machine": "AMD64",
        "is_dll": False,
        "is_exe": True,
        "subsystem": "windows-console",
        "imports": rows,
        "imported_functions": functions,
        "exports": [],
        "exported_functions": [],
        "sections": [],
        "capabilities": [],
    }


def _report(imports: dict[str, list[str]], *, registry_strings: list[str] | None = None, legacy_imports: bool = False) -> Report:
    inv = Investigation()
    artifact = inv.add_file_artifact(
        sha256=SHA,
        name="sample.exe",
        size=1024,
        hashes={"sha256": SHA},
        detected_type="pe",
        detected_family="executable",
        detected_mime="application/vnd.microsoft.portable-executable",
        description="Windows PE executable",
    )
    run = inv.begin_run(
        analyzer_id="pe",
        analyzer_version="1.0.0",
        analyzer_title="Windows PE",
        artifact_id=artifact.id,
    )
    details = _pe_details(imports)
    if legacy_imports:
        details.pop("imported_functions")
    pe_result = AnalyzerResult(
        name="pe",
        title="Windows PE",
        applies=True,
        status="completed",
        analyzer_version="1.0.0",
        details=details,
    )
    inv.ingest_result("pe", "1.0.0", artifact.id, pe_result, run)

    if registry_strings:
        str_run = inv.begin_run(
            analyzer_id="strings",
            analyzer_version="1.0.0",
            analyzer_title="Strings and indicators",
            artifact_id=artifact.id,
        )
        finding = Finding(
            id="strings.registry",
            title="Registry path strings",
            summary="The file contains Windows registry path strings.",
            category="system",
            severity="low",
            confidence="high",
            analyzer="strings",
            tags=["registry"],
            evidence=[
                Evidence(kind="string", summary="Registry path", analyzer="strings", value=value)
                for value in registry_strings
            ],
        )
        inv.ingest_result(
            "strings",
            "1.0.0",
            artifact.id,
            AnalyzerResult(
                name="strings",
                title="Strings and indicators",
                applies=True,
                status="completed",
                analyzer_version="1.0.0",
                findings=[finding],
                details={"registry": list(registry_strings)},
            ),
            str_run,
        )

    report = Report(
        schema_version=1,
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
        identity=_identity(),
        overview="",
        next_steps=[],
        hashes={"sha256": SHA},
        findings=list(inv.findings),
        sections=[pe_result],
        limits={"executed": False, "static_only": True},
        capabilities=[],
        engine={"name": "exsoftware", "version": "test", "schema": "exsoftware.report"},
        root_artifact_id=artifact.id,
        artifacts=list(inv.artifacts.values()),
        relationships=list(inv.relationships),
        observations=list(inv.observations),
        evidence_store=list(inv.evidence),
        analyzer_runs=list(inv.runs),
    )
    report.composition = compose(report).to_dict()
    return report


def _caps(report: Report) -> dict[str, dict]:
    return {item["id"]: item for item in report.composition["capabilities"]}


def test_createprocess_import_yields_process_creation_capability():
    caps = _caps(_report({"KERNEL32.dll": ["CreateProcessW"]}))
    cap = caps["CAP.PROCESS.PE_CREATE_PROCESS.001"]
    assert cap["family"] == "PROCESS"
    assert "CreateProcessW" in " ".join(cap["evidence"])


def test_winhttp_open_and_send_request_yield_http_capability():
    caps = _caps(_report({"winhttp.dll": ["WinHttpOpen", "WinHttpSendRequest"]}))
    cap = caps["CAP.NETWORK.PE_WINHTTP_CLIENT.001"]
    assert cap["confidence"] == "high"
    assert "WinHttpOpen" in " ".join(cap["evidence"])
    assert "WinHttpSendRequest" in " ".join(cap["evidence"])


def test_remote_process_injection_compound_rule():
    report = _report(
        {
            "kernel32.dll": [
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ]
        }
    )
    caps = _caps(report)
    cap = caps["CAP.INJECTION.PE_CLASSIC_REMOTE_THREAD.001"]
    assert cap["confidence"] == "high"
    assert {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"} <= set(
        " ".join(cap["evidence"]).replace("kernel32.dll!", "").split()
    ) or all(name in " ".join(cap["evidence"]) for name in ("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"))


def test_registry_create_and_set_value_yield_registry_modify_capability():
    caps = _caps(_report({"advapi32.dll": ["RegCreateKeyExW", "RegSetValueExW"]}))
    assert "CAP.REGISTRY.PE_MODIFY.001" in caps


def test_service_manager_create_service_yields_service_capability():
    caps = _caps(_report({"advapi32.dll": ["OpenSCManagerW", "CreateServiceW"]}))
    cap = caps["CAP.PERSISTENCE.PE_SERVICE_CREATE.001"]
    assert cap["confidence"] == "high"


def test_cryptoapi_and_cng_encrypt_imports_yield_crypto_capabilities():
    caps = _caps(_report({"bcrypt.dll": ["BCryptEncrypt"], "advapi32.dll": ["CryptEncrypt"]}))
    assert "CAP.CRYPTOGRAPHY.PE_CNG.001" in caps
    assert "CAP.CRYPTOGRAPHY.PE_CRYPTOAPI.001" in caps


def test_debugger_detection_imports_yield_anti_analysis_capability():
    caps = _caps(_report({"kernel32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]}))
    assert "CAP.ANTI_ANALYSIS.PE_DEBUGGER_CHECK.001" in caps


def test_ansi_unicode_variants_normalize_to_one_capability():
    report = _report({"kernel32.dll": ["CreateProcessA", "CreateProcessW"]})
    caps = [item for item in report.composition["capabilities"] if item["id"] == "CAP.PROCESS.PE_CREATE_PROCESS.001"]
    assert len(caps) == 1
    assert "CreateProcessA" in " ".join(caps[0]["evidence"])
    assert "CreateProcessW" in " ".join(caps[0]["evidence"])


def test_crt_leading_underscore_imports_remain_matchable():
    assert normalize_windows_api_name("_wsystem") == "_wsystem"
    assert normalize_windows_api_name("_wpopen") == "_wpopen"

    caps = _caps(_report({"msvcrt.dll": ["_wsystem", "_wpopen"]}))
    assert "CAP.SHELL.PE_C_RUNTIME_SYSTEM.001" in caps


def test_import_and_stdcall_decoration_normalizes_without_breaking_crt_names():
    assert normalize_windows_api_name("__imp_CreateFileW") == "CreateFile"
    assert normalize_windows_api_name("__imp__CreateFileW@28") == "CreateFile"
    assert normalize_windows_api_name("_CreateFileW@28") == "CreateFile"
    assert normalize_windows_api_name("_wsystem") == "_wsystem"


def test_dnsquery_underscore_ansi_unicode_aliases_normalize_to_dnsquery():
    assert normalize_windows_api_name("DnsQuery_A") == "DnsQuery"
    assert normalize_windows_api_name("DnsQuery_W") == "DnsQuery"

    caps = _caps(_report({"dnsapi.dll": ["DnsQuery_A", "DnsQuery_W"]}))
    assert "CAP.NETWORK.PE_DNS_LOOKUP.001" in caps


def test_canonical_normalization_is_deterministic_for_getaddrinfo_variants():
    names = ["getaddrinfo", "GetAddrInfo", "GetAddrInfoA", "GetAddrInfoW"]
    expected = ["getaddrinfo", "getaddrinfo", "getaddrinfo", "getaddrinfo"]
    assert [normalize_windows_api_name(name) for name in names] == expected
    assert [item["normalized_name"] for item in _pe_details({"ws2_32.dll": names})["imported_functions"]] == expected


def test_winsock_generic_symbol_from_unrelated_dll_does_not_trigger_socket_capability():
    caps = _caps(_report({"ws2_32.dll": [], "customnet.dll": ["send", "connect"]}))
    assert "CAP.NETWORK.PE_WINSOCK.001" not in caps


def test_winsock_generic_symbol_from_winsock_dll_triggers_socket_capability():
    caps = _caps(_report({"ws2_32.dll": ["socket", "send"]}))
    assert "CAP.NETWORK.PE_WINSOCK.001" in caps


def test_ntqueryinformationprocess_alone_is_not_high_confidence_debugger_detection():
    caps = _caps(_report({"ntdll.dll": ["NtQueryInformationProcess"]}))
    assert "CAP.ANTI_ANALYSIS.PE_DEBUGGER_CHECK.001" not in caps
    process_query = caps["CAP.PROCESS.PE_NT_PROCESS_QUERY.001"]
    assert process_query["family"] == "PROCESS"
    assert process_query["confidence"] == "medium"


def test_getasynckeystate_does_not_become_input_hook_claim():
    caps = _caps(_report({"user32.dll": ["GetAsyncKeyState"]}))
    assert "CAP.UI.PE_INPUT_HOOKS.001" not in caps
    keyboard_state = caps["CAP.UI.PE_KEYBOARD_STATE.001"]
    assert keyboard_state["title"] == "Keyboard state observation"
    assert "hook" not in keyboard_state["title"].lower()


def test_generic_sleep_does_not_become_anti_analysis_claim():
    caps = _caps(_report({"kernel32.dll": ["Sleep"]}))
    assert "CAP.ANTI_ANALYSIS.PE_TIMING.001" not in caps
    timing = caps["CAP.TIMING.PE_TIMING_DELAY.001"]
    assert timing["family"] == "TIMING"
    assert "anti-analysis" not in timing["title"].lower()


def test_toolhelp_process_enumeration_requires_compound_evidence():
    snapshot_only = _caps(_report({"kernel32.dll": ["CreateToolhelp32Snapshot"]}))
    assert "CAP.DISCOVERY.PE_TOOLHELP_PROCESS_ENUM.001" not in snapshot_only

    caps = _caps(_report({"kernel32.dll": ["CreateToolhelp32Snapshot", "Process32FirstW"]}))
    assert "CAP.DISCOVERY.PE_TOOLHELP_PROCESS_ENUM.001" in caps


def test_generic_dynamic_api_does_not_create_malicious_finding():
    report = _report({"kernel32.dll": ["GetProcAddress"]})
    text = " ".join(item.title + " " + item.summary for item in report.findings).lower()
    assert "malware" not in text
    assert "steal" not in text
    assert "CAP.DYNAMIC_LOADING.PE_DYNAMIC_API.001" in _caps(report)


def test_missing_imports_do_not_crash_or_invent_capabilities():
    report = _report({})
    assert report.composition["capabilities"] == []


def test_unknown_ordinals_are_preserved_without_false_capability_matches():
    report = _report({"kernel32.dll": ["#17"]})
    assert report.composition["capabilities"] == []
    assert any(ev.value == "#17" and ev.extra.get("import_kind") == "ordinal" for ev in report.evidence_store)


def test_evidence_links_survive_from_observation_to_capability():
    report = _report({"kernel32.dll": ["CreateProcessW"]})
    cap = _caps(report)["CAP.PROCESS.PE_CREATE_PROCESS.001"]
    assert cap["refs"]["evidence_ids"]
    assert cap["refs"]["observation_ids"]
    evidence_ids = {item.id for item in report.evidence_store}
    observation_ids = {item.id for item in report.observations}
    assert set(cap["refs"]["evidence_ids"]) <= evidence_ids
    assert set(cap["refs"]["observation_ids"]) <= observation_ids


def test_existing_legacy_pe_import_details_remain_compatible():
    report = _report({"kernel32.dll": ["CreateProcessW"]}, legacy_imports=True)
    payload = report.to_dict()
    restored = Report.from_dict(payload)
    restored.composition = compose(restored).to_dict()
    assert restored.schema_version == 1
    assert "CAP.PROCESS.PE_CREATE_PROCESS.001" in _caps(restored)


def test_autorun_registry_capability_requires_api_and_path_string():
    no_string = _caps(_report({"advapi32.dll": ["RegSetValueExW"]}))
    assert "CAP.PERSISTENCE.PE_AUTORUN_REGISTRY.001" not in no_string

    with_string = _caps(
        _report(
            {"advapi32.dll": ["RegSetValueExW"]},
            registry_strings=[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
        )
    )
    assert "CAP.PERSISTENCE.PE_AUTORUN_REGISTRY.001" in with_string


def test_rendered_report_shows_capability_evidence_and_confidence():
    report = _report({"winhttp.dll": ["WinHttpOpen", "WinHttpSendRequest"]})
    text = render_text(report)
    assert "WinHTTP client behavior" in text
    assert "Evidence:" in text
    assert "WinHttpSendRequest" in text
    assert "Confidence: high" in text
    assert "PE capability inference is based on static imports" in text
