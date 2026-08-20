"""Validate child analyzer protocol messages before they touch the investigation graph."""

from __future__ import annotations

from typing import Any

from ..models import AnalyzerError, AnalyzerResult, Finding
from .protocol import (
    CERTAINTIES,
    CONFIDENCES,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    REASON_INVALID_RESPONSE,
    SEVERITIES,
    STATUSES,
)


class ProtocolError(ValueError):
    def __init__(self, message: str, *, code: str = REASON_INVALID_RESPONSE) -> None:
        super().__init__(message)
        self.code = code


def validate_request(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("request is not an object")
    if data.get("protocol") != PROTOCOL_NAME:
        raise ProtocolError("unsupported protocol name")
    if data.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    for key in ("analyzer_id", "analyzer_version", "artifact_id", "input", "identity", "context", "limits"):
        if key not in data:
            raise ProtocolError(f"missing request field {key}")
    if not isinstance(data["analyzer_id"], str) or not data["analyzer_id"]:
        raise ProtocolError("analyzer_id must be a non-empty string")
    if not isinstance(data["input"], dict):
        raise ProtocolError("input must be an object")
    if not isinstance(data["identity"], dict):
        raise ProtocolError("identity must be an object")
    if not isinstance(data["context"], dict):
        raise ProtocolError("context must be an object")
    if not isinstance(data["limits"], dict):
        raise ProtocolError("limits must be an object")
    return data


def validate_response(
    data: Any,
    *,
    analyzer_id: str,
    analyzer_version: str,
    artifact_id: str,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProtocolError("response is not an object")
    if data.get("protocol") != PROTOCOL_NAME:
        raise ProtocolError("unsupported protocol name")
    if data.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if data.get("analyzer_id") != analyzer_id:
        raise ProtocolError("analyzer_id does not match the request")
    if data.get("analyzer_version") != analyzer_version:
        raise ProtocolError("analyzer_version does not match the request")
    status = data.get("status")
    if status not in STATUSES:
        raise ProtocolError("status is missing or not an allowed value")
    result = data.get("result")
    if result is None:
        raise ProtocolError("result is required")
    if not isinstance(result, dict):
        raise ProtocolError("result must be an object")
    _validate_result(result, analyzer_id=analyzer_id, analyzer_version=analyzer_version, artifact_id=artifact_id)
    result_status = result.get("status")
    if result_status not in STATUSES:
        raise ProtocolError("result.status is missing or not an allowed value")
    if result_status != status:
        raise ProtocolError("top-level status does not match result.status")
    if data.get("error") is not None and not isinstance(data.get("error"), dict):
        raise ProtocolError("error must be an object or null")
    if data.get("timing") is not None and not isinstance(data.get("timing"), dict):
        raise ProtocolError("timing must be an object or null")
    if "artifacts" in result or "relationships" in result or "observations" in result:
        raise ProtocolError("child result may not include investigation graph objects")
    return data


def _validate_result(
    result: dict[str, Any],
    *,
    analyzer_id: str,
    analyzer_version: str,
    artifact_id: str,
) -> None:
    name = result.get("name") or result.get("analyzer_id")
    if name != analyzer_id:
        raise ProtocolError("result analyzer identity does not match the request")
    if result.get("analyzer_version") not in {None, analyzer_version}:
        if result.get("analyzer_version") != analyzer_version:
            raise ProtocolError("result analyzer_version does not match the request")
    result_artifact = result.get("artifact_id")
    if result_artifact not in {None, "", artifact_id}:
        raise ProtocolError("result artifact_id does not match the request")
    if not isinstance(result.get("applies", True), bool):
        raise ProtocolError("result.applies must be a boolean")
    if not isinstance(result.get("skipped", False), bool):
        raise ProtocolError("result.skipped must be a boolean")
    if result.get("skip_reason") is not None and not isinstance(result.get("skip_reason"), str):
        raise ProtocolError("result.skip_reason must be a string")
    if not isinstance(result.get("details", {}), dict):
        raise ProtocolError("result.details must be an object")
    if not isinstance(result.get("errors", []), list):
        raise ProtocolError("result.errors must be an array")
    for err in result.get("errors") or []:
        if not isinstance(err, dict):
            raise ProtocolError("each error must be an object")
        if not isinstance(err.get("message", ""), str):
            raise ProtocolError("error.message must be a string")
    findings = result.get("findings") or []
    if not isinstance(findings, list):
        raise ProtocolError("result.findings must be an array")
    if len(findings) > 10_000:
        raise ProtocolError("result.findings exceeds the allowed count")
    for finding in findings:
        _validate_finding(finding, analyzer_id=analyzer_id, artifact_id=artifact_id)


def _validate_finding(finding: Any, *, analyzer_id: str, artifact_id: str) -> None:
    if not isinstance(finding, dict):
        raise ProtocolError("each finding must be an object")
    for required in ("title", "summary", "category"):
        if not isinstance(finding.get(required, ""), str):
            raise ProtocolError(f"finding.{required} must be a string")
    severity = finding.get("severity", "info")
    if severity not in SEVERITIES:
        raise ProtocolError("finding.severity is not an allowed value")
    confidence = finding.get("confidence", "medium")
    if confidence not in CONFIDENCES:
        raise ProtocolError("finding.confidence is not an allowed value")
    certainty = finding.get("certainty")
    if certainty is not None and certainty not in CERTAINTIES:
        raise ProtocolError("finding.certainty is not an allowed value")
    owner = finding.get("analyzer_id") or finding.get("analyzer")
    if owner not in {None, "", analyzer_id}:
        raise ProtocolError("finding analyzer identity does not match the request")
    finding_artifact = finding.get("artifact_id")
    if finding_artifact not in {None, "", artifact_id}:
        raise ProtocolError("finding artifact_id does not match the request")
    if finding.get("evidence") is not None and not isinstance(finding.get("evidence"), list):
        raise ProtocolError("finding.evidence must be an array")
    for evidence in finding.get("evidence") or []:
        if not isinstance(evidence, dict):
            raise ProtocolError("each evidence item must be an object")
        ev_artifact = evidence.get("artifact_id")
        if ev_artifact not in {None, "", artifact_id}:
            raise ProtocolError("evidence artifact_id does not match the request")
    for key in ("evidence_ids", "observation_ids", "tags"):
        if finding.get(key) is not None and not isinstance(finding.get(key), list):
            raise ProtocolError(f"finding.{key} must be an array")


def result_from_payload(data: dict[str, Any]) -> AnalyzerResult:
    payload = data["result"]
    result = AnalyzerResult.from_dict(payload)
    result.findings = [Finding.from_dict(item) for item in payload.get("findings") or []]
    if not result.errors and payload.get("errors"):
        result.errors = [AnalyzerError.from_dict(item) for item in payload["errors"]]
    return result
