"""Conservative software-category labels. Not malware verdicts."""

from __future__ import annotations

from ..models import Artifact, Report

CATEGORIES: dict[str, str] = {
    "windows_native_executable": "Windows native executable",
    "windows_native_library": "Windows native library",
    "linux_native_executable": "Linux native executable or library",
    "macos_native_executable": "macOS native executable or library",
    "python_script": "Python script",
    "powershell_script": "PowerShell script",
    "javascript_script": "JavaScript source",
    "shell_script": "Shell script",
    "java_archive": "Java archive",
    "android_application_package": "Android application package",
    "python_wheel": "Python wheel/package",
    "zip_software_bundle": "ZIP software bundle",
    "document": "Document",
    "image_resource": "Image/resource",
    "library": "Library",
    "bytecode": "Bytecode",
    "configuration": "Configuration or text",
    "unknown_binary": "Unknown binary",
}


def classify(report: Report, artifact: Artifact | None) -> tuple[str, str]:
    detected = (artifact.detected_type if artifact else None) or report.identity.detected_type
    family = (artifact.detected_family if artifact else None) or report.identity.detected_family
    pe = _pe_details(report, artifact.id if artifact else report.root_artifact_id)
    if detected == "pe":
        if pe.get("is_dll"):
            return "windows_native_library", CATEGORIES["windows_native_library"]
        return "windows_native_executable", CATEGORIES["windows_native_executable"]
    mapping = {
        "elf": "linux_native_executable",
        "macho64": "macos_native_executable",
        "macho32": "macos_native_executable",
        "macho-fat": "macos_native_executable",
        "python": "python_script",
        "powershell": "powershell_script",
        "javascript": "javascript_script",
        "typescript": "javascript_script",
        "shell": "shell_script",
        "batch": "shell_script",
        "jar": "java_archive",
        "apk": "android_application_package",
        "wheel": "python_wheel",
        "zip": "zip_software_bundle",
        "docx": "document",
        "xlsx": "document",
        "pptx": "document",
        "pdf": "document",
        "doc": "document",
        "xls": "document",
        "ppt": "document",
        "rtf": "document",
        "png": "image_resource",
        "jpeg": "image_resource",
        "gif": "image_resource",
        "bmp": "image_resource",
        "webp": "image_resource",
        "ico": "image_resource",
        "java-class": "bytecode",
        "pyc": "bytecode",
        "json": "configuration",
        "xml": "configuration",
        "toml": "configuration",
        "text": "configuration",
        "html": "configuration",
    }
    key = mapping.get(detected)
    if key:
        return key, CATEGORIES[key]
    if family == "executable":
        return "windows_native_executable", CATEGORIES["windows_native_executable"]
    if family == "image":
        return "image_resource", CATEGORIES["image_resource"]
    if detected == "unknown":
        return "unknown_binary", CATEGORIES["unknown_binary"]
    return "unknown_binary", CATEGORIES["unknown_binary"]


def _pe_details(report: Report, artifact_id: str | None) -> dict:
    if not artifact_id:
        return {}
    for run in report.analyzer_runs:
        if run.analyzer_id == "pe" and run.artifact_id == artifact_id and run.status == "completed":
            return run.details or {}
    return {}
