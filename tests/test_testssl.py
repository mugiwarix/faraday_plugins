import json
import os
from unittest.mock import patch

import pytest

from faraday_plugins.plugins.plugin import PluginBase
from faraday_plugins.plugins.repo.testssl.plugin import (
    EvidenceLimit,
    MAX_INPUT_BYTES,
    MAX_RAW_RECORDS,
    TestsslPlugin as EvidencePlugin,
    createPlugin,
)


TARGET = "10.0.0.1"


def record(finding_id="SSLv2", text="not offered", severity="OK", **kwargs):
    return {"id": finding_id, "ip": f"{TARGET}/{TARGET}", "port": "443",
            "severity": severity, "finding": text, **kwargs}


def plugin(**kwargs):
    return createPlugin(target=TARGET, port=443, finding_ids=["SSLv2", "SSLv3"], **kwargs)


def findings(parser):
    return parser.get_data()["hosts"][0]["services"][0]["vulnerabilities"]


def test_factory_consumes_keyword_metadata():
    with patch.object(PluginBase, "__init__", autospec=True, return_value=None) as base:
        parser = createPlugin(target=TARGET, port=443, finding_ids={"SSLv2"}, max_records=5)
    base.assert_called_once_with(parser)
    assert isinstance(parser, EvidencePlugin)
    assert not createPlugin().auto_load
    with pytest.raises(ValueError, match="requires"):
        createPlugin().parseOutputString("[]")


def test_bound_report_preserves_evidence_order_and_duplicates():
    raw = "  not offered\r\n\t✓  "
    entries = [record("service", "HTTP", "INFO"), record(text=raw), record(text=raw),
               record("SSLv3", "offered", "cRiTiCaL"), record("TLS1_2", "offered"),
               record("engine_problem", "retry", "WARN"), record("unexpected", "failure", "ERROR"),
               record("scanProblem", "problem", "WARN"), record("scanTime", "1 second", "INFO")]
    parser = plugin(ignore_info=True, min_severity="critical", max_severity="critical", hostname_resolution=True)
    with patch("socket.gethostbyname", side_effect=AssertionError("Unexpected DNS")):
        parser.parseOutputString(json.dumps(entries))
    report = parser.get_data()
    assert set(report) == {"hosts", "command"}
    host = report["hosts"][0]
    assert len(report["hosts"]) == 1 and host["ip"] == TARGET and host["hostnames"] == []
    service = host["services"][0]
    assert len(host["services"]) == 1 and service["port"] == 443 and service["protocol"] == "tcp"
    evidence = service["vulnerabilities"]
    assert [item["name"] for item in evidence] == [
        "service", "SSLv2", "SSLv2", "SSLv3", "TLS1_2", "engine_problem", "unexpected", "scanProblem", "scanTime"]
    assert evidence[1] == {"name": "SSLv2", "desc": raw, "data": "OK",
                           "severity": "unclassified", "type": "Vulnerability"}
    assert evidence[3]["data"] == "CRITICAL" and evidence[3]["severity"] == "critical"
    assert parser.get_summary()["services_vulns"] == 9
    assert json.loads(parser.get_json())["hosts"] == report["hosts"]


@pytest.mark.parametrize("severity,text", [
    ("WARN", "retry"), ("WARNING", "retry"), ("UNKNOWN", "retry"), ("", "retry"),
    ("PROMPT", "retry"), ("SPECIAL", "retry"), ("ERROR", "retry"), ("FATAL", "retry"),
    ("INFO", "check skipped"), ("INFO", "scan incomplete"), ("OK", "error reading response"),
    ("INFO", "Warning: no result"), ("OK", "skipping this check"),
    ("INFO", "could not test"), ("INFO", "check timed out"), ("INFO", "unfamiliar diagnostic"),
])
def test_all_diagnostics_preserved_without_requested_id_filter(severity, text):
    ids = ["cipherlist_LOW", "cipherlist_OBSOLETED", "cipherlist_EXPORT"]
    parser = createPlugin(target=TARGET, port=443, finding_ids=ids)
    entries = [record(finding_id) for finding_id in ids]
    entries += [record("unrelated", "retry", "WARN"), record("scanTime", "check skipped", "INFO"),
                record("other", text, severity)]
    parser.parseOutputString(json.dumps(entries))
    evidence = findings(parser)
    assert [item["name"] for item in evidence] == [entry["id"] for entry in entries]
    assert [item["desc"] for item in evidence] == [entry["finding"] for entry in entries]
    assert [item["data"] for item in evidence] == [entry["severity"].upper() for entry in entries]


@pytest.mark.parametrize("severity,expected", [
    ("INFO", "info"), ("LOW", "low"), ("MEDIUM", "med"), ("HIGH", "high"),
    ("CRITICAL", "critical"), ("ERROR", "unclassified"), ("OK", "unclassified"),
])
def test_severity_normalization_not_verdicts(severity, expected):
    parser = plugin()
    parser.parseOutputString(json.dumps([record(severity=severity)]))
    assert findings(parser)[0]["data"] == severity
    assert findings(parser)[0]["severity"] == expected


@pytest.mark.parametrize("payload", [
    b"", b"{", b"{}", b"null", b"[{}]", b"[] trailing", b"\xff",
    b'[{"id":"SSLv2","id":"SSLv3"}]', b'[{"x":{"a":1,"a":2}}]',
    b'[{"x":NaN}]', b'[{"x":Infinity}]', b'[{"x":-Infinity}]', b'[{"x":1e999}]',
    b'[{"x":1.0}]', b'[{"x":12345678901234567890}]', b"[" * 2000 + b"]" * 2000,
])
def test_strict_json_rejected_atomically(payload):
    parser = plugin()
    parser.parseOutputString(json.dumps([record()]))
    with pytest.raises(ValueError):
        parser.parseOutputString(payload)
    assert parser.get_data()["hosts"] == []


@pytest.mark.parametrize("field,value", [
    ("id", None), ("id", 1), ("id", ""), ("finding", []), ("finding", "\ud800"),
    ("severity", True), ("port", True), ("port", "0443"), ("port", "8443"),
    ("port", 443.0), ("port", None), ("ip", "10.0.0.2"), ("ip", "other/10.0.0.1"),
    ("ip", "10.0.0.1/10.0.0.2"), ("ip", "10.0.0.1/10.0.0.1/10.0.0.1"),
    ("ip", ""), ("ip", "::ffff:10.0.0.1"), ("extra", "unknown"), ("cve", []),
])
def test_invalid_record_or_foreign_endpoint_even_when_unrequested(field, value):
    parser = plugin()
    entries = [record(), record("unrequested", **{field: value})] if field != "id" else [record(), {**record(), field: value}]
    with pytest.raises(ValueError):
        parser.parseOutputString(json.dumps(entries))
    assert parser.get_data()["hosts"] == []


def test_integer_port_and_bounded_optional_text():
    parser = plugin()
    parser.parseOutputString(json.dumps([record(port=443, cve="CVE-2016-0800", cwe="CWE-310", hint="raw")]))
    assert len(findings(parser)) == 1


@pytest.mark.parametrize("field,value", [
    ("id", "x" * 129), ("finding", "x" * 8193), ("finding", "é" * 4097),
    ("severity", "x" * 33), ("ip", "x" * 32), ("port", "1" * 6), ("hint", "x" * 8193),
])
def test_text_byte_limits(field, value):
    with pytest.raises(EvidenceLimit):
        plugin().parseOutputString(json.dumps([{**record(), field: value}]))


def test_input_and_raw_record_limits():
    for payload in [b" " * (MAX_INPUT_BYTES + 1), "é" * (MAX_INPUT_BYTES // 2 + 1),
                    json.dumps([record("unrequested")] * (MAX_RAW_RECORDS + 1))]:
        with pytest.raises(EvidenceLimit):
            plugin().parseOutputString(payload)
    with pytest.raises(EvidenceLimit, match="Too many evidence records"):
        plugin().parseOutputString(json.dumps([record("unrequested")] * MAX_RAW_RECORDS))


def test_output_record_limits_include_duplicates_service_and_errors():
    parser = plugin()
    parser.parseOutputString(json.dumps([record()] * 64))
    assert len(findings(parser)) == 64
    for entries in [[record()] * 65, [record("service")] * 65, [record("unknown", severity="ERROR")] * 65,
                    [record("other", severity="WARN")] * 65, [record("scanTime", "check skipped", "INFO")] * 65]:
        with pytest.raises(EvidenceLimit):
            parser.parseOutputString(json.dumps(entries))
        assert parser.get_data()["hosts"] == []
    with pytest.raises(EvidenceLimit):
        plugin(max_records=1).parseOutputString(json.dumps([record(), record("service")]))


@pytest.mark.parametrize("kwargs", [
    {"target": "example.com"}, {"target": "010.0.0.1"}, {"target": "0.0.0.0"}, {"target": "224.0.0.1"},
    {"target": "255.255.255.255"}, {"target": "240.0.0.1"}, {"target": "0.1.2.3"},
    {"target": "10.0.0.1:443"}, {"target": "::1"}, {"port": True}, {"port": "443"},
    {"port": 0}, {"port": 65536}, {"finding_ids": "SSLv2"}, {"finding_ids": []},
    {"finding_ids": [None]}, {"finding_ids": [""]}, {"max_records": 65}, {"max_records": 0},
    {"max_records": True}, {"finding_ids": ["x"] * 65},
])
def test_binding_validation(kwargs):
    with pytest.raises(ValueError):
        createPlugin(**{"target": TARGET, "port": 443, "finding_ids": ["SSLv2"], **kwargs})


def test_file_reader_regular_bounded_nofollow(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps([record()]), encoding="utf-8")
    parser = plugin()
    parser.processReport(path)
    assert len(findings(parser)) == 1
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        parser.processReport(link)
    assert parser.get_data()["hosts"] == []
    path.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
    with pytest.raises(EvidenceLimit):
        parser.processReport(path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular"):
        parser._parse_filename(fifo)


def test_empty_evidence_is_not_synthesized():
    parser = plugin()
    parser.parseOutputString("[]")
    assert findings(parser) == []
