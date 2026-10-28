"""Porco's result importer parses evidence, never decides vulnerability status."""

import json
from unittest.mock import patch

import pytest

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday_plugins.plugins.repo.porco_validator.plugin import (
    MAX_RESULT_BYTES,
    MAX_TASKS,
    PorcoValidatorPlugin,
    createPlugin,
)


@pytest.fixture
def result():
    return {
        "schema_version": 1,
        "validator_id": "a" * 32,
        "validator_digest": "b" * 64,
        "runner": {"dispatcher_version": "3.9.1", "platform": "linux/amd64", "version": "1"},
        "tasks": [{
            "task_id": "c" * 32, "state": "COMPLETED", "error": "",
            "stdout": '  <nmaprun>\r\n\tTLSv1.0 ✓</nmaprun>\n {"verdict":"TRUE_POSITIVE"}  ',
            "stderr": " \twarning\r\n", "started_at": 10, "finished_at": 11,
        }],
    }


@pytest.fixture(scope="module")
def manager():
    return PluginsManager(hostname_resolution=False, ignore_info=False)


def test_factory_and_manager(manager):
    assert isinstance(createPlugin(), PorcoValidatorPlugin)
    assert manager.get_plugin("porcovalidator").id == "PorcoValidator"


def test_analyzer_and_report_preserve_raw_evidence(result, manager, tmp_path):
    path = tmp_path / "validator-result.json"
    path.write_text(json.dumps(result), encoding="utf-8")
    plugin = ReportAnalyzer(manager).get_plugin(str(path))
    assert plugin.id == "PorcoValidator"
    with patch("socket.gethostbyname", side_effect=AssertionError("Unexpected DNS lookup")):
        plugin.processReport(path)
    data = plugin.get_data()
    assert data["validator_result"] == result
    assert data["hosts"] == []
    assert set(data) == {"hosts", "command", "validator_result"}
    assert plugin.get_summary()["services_vulns"] == 0
    assert plugin.get_summary()["hosts_vulns"] == 0
    assert json.loads(plugin.get_json())["validator_result"] == result


@pytest.mark.parametrize("state", ["COMPLETED", "ERROR", "INTERRUPTED", "NOT_RUN", "TRUE_POSITIVE", "UNKNOWN"])
def test_no_status_or_trust_semantics(result, state):
    result["tasks"][0].update(state=state, error="UNTRUSTED", started_at=11, finished_at=10)
    result["runner"] = {"dispatcher_version": "untrusted", "platform": "untrusted", "version": "untrusted"}
    result["tasks"].append(dict(result["tasks"][0]))  # Binding/duplicate task IDs belong to Porco.
    plugin = createPlugin()
    with patch.object(plugin, "createAndAddHost", side_effect=AssertionError("Must not create findings")):
        plugin.parseOutputString(json.dumps(result))
    assert plugin.get_data()["validator_result"] == result
    assert plugin.get_data()["hosts"] == []
    assert plugin._service_cache == {}
    assert plugin._vulns_cache == {}


@pytest.mark.parametrize("payload", [
    b"", b"{", b"{} trailing", b"\xff", b"[]", b"null",
    b'{"schema_version":1,"schema_version":1}',
    b'{"x":{"duplicate":1,"duplicate":2}}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}',
    b'{"x":123456789012345678901}', b"[" * 1000 + b"]" * 1000,
    b" " * (MAX_RESULT_BYTES + 1),
])
def test_strict_json_rejected(payload):
    plugin = createPlugin()
    with pytest.raises(ValueError):
        plugin.parseOutputString(payload)
    assert "validator_result" not in plugin.get_data()
    assert plugin.get_data()["hosts"] == []


def test_nested_duplicates_rejected_in_real_envelope(result):
    payload = json.dumps(result).replace('"state": "COMPLETED"', '"state": "COMPLETED", "state": "ERROR"')
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        createPlugin().parseOutputString(payload)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("schema_version", 1.0),
    ("validator_id", "not-an-id"), ("validator_digest", "not-a-digest"),
    ("tasks", []), ("tasks", {}), ("runner", []),
    ("tasks", [{}] * (MAX_TASKS + 1)),
])
def test_envelope_structure(result, field, value):
    result[field] = value
    with pytest.raises(ValueError):
        createPlugin().parseOutputString(json.dumps(result))


@pytest.mark.parametrize("field,value", [
    ("stdout", "x" * 32769), ("stdout", "é" * 16385), ("stderr", "x" * 2049),
    ("state", "x" * 1025), ("error", "x" * 1025), ("stdout", {}), ("stdout", "\ud800"),
    ("started_at", True), ("finished_at", 1.5), ("started_at", -1),
    ("finished_at", 253402300800), ("task_id", "unknown"),
])
def test_task_structure_and_string_byte_limits(result, field, value):
    result["tasks"][0][field] = value
    with pytest.raises(ValueError):
        createPlugin().parseOutputString(json.dumps(result))


@pytest.mark.parametrize("location", ["envelope", "runner", "task"])
@pytest.mark.parametrize("field", ["verdict", "activity_id", "target", "claims", "vulnerabilities"])
def test_no_claimed_fields_accepted(result, location, field):
    obj = result if location == "envelope" else result["runner"] if location == "runner" else result["tasks"][0]
    obj[field] = "TRUE_POSITIVE"
    with pytest.raises(ValueError):
        createPlugin().parseOutputString(json.dumps(result))


@pytest.mark.parametrize("mutation", ["unrelated", "schema", "duplicate", "nonfinite", "extension"])
def test_autodetection_avoids_unrelated_or_invalid_json(result, manager, tmp_path, mutation):
    payload = json.dumps(result)
    path = tmp_path / "validator-result.json"
    if mutation == "unrelated":
        payload = '{"schema_version":1,"tasks":[]}'
    elif mutation == "schema":
        payload = payload.replace('"schema_version": 1', '"schema_version": 2')
    elif mutation == "duplicate":
        payload = payload.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    elif mutation == "nonfinite":
        payload = payload.replace('"started_at": 10', '"started_at": NaN')
    elif mutation == "extension":
        path = path.with_suffix(".txt")
    path.write_text(payload, encoding="utf-8")
    detected = ReportAnalyzer(manager).get_plugin(str(path))
    assert detected is None or detected.id != "PorcoValidator"


def test_forced_filename_does_not_bypass_validation(manager, tmp_path):
    path = tmp_path / "invalid_faraday_PorcoValidator.json"
    path.write_text("{}", encoding="utf-8")
    plugin = ReportAnalyzer(manager).get_plugin(str(path))
    assert plugin.id == "PorcoValidator"
    with pytest.raises(ValueError):
        plugin.processReport(path)


def test_file_size_read_is_bounded(tmp_path):
    path = tmp_path / "validator-result.json"
    path.write_bytes(b" " * (MAX_RESULT_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        createPlugin().processReport(path)


def test_invalid_second_report_clears_previous_result(result):
    plugin = createPlugin()
    plugin.parseOutputString(json.dumps(result))
    with pytest.raises(ValueError):
        plugin.parseOutputString("{}")
    assert "validator_result" not in plugin.get_data()
