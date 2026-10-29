"""Bound testssl.sh evidence parser; vulnerability verdicts belong to consumers."""

import ipaddress
import json
import os
import stat

from faraday_plugins.plugins.plugin import PluginJsonFormat


MAX_INPUT_BYTES = 262144
MAX_RAW_RECORDS = 2048
MAX_RECORDS = 64
RECORD_KEYS = {"id", "ip", "port", "severity", "finding"}
OPTIONAL_KEYS = {"cve", "cwe", "hint"}


class EvidenceLimit(ValueError):
    """Evidence exceeds a resource limit; never return truncated evidence."""


def _text(value, limit):
    if type(value) is not str:
        raise ValueError("Expected evidence string")
    if len(value) > limit:
        raise EvidenceLimit("Evidence string exceeds limit")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Invalid evidence Unicode") from None
    if size > limit:
        raise EvidenceLimit("Evidence string exceeds limit")
    return value


def _target(value):
    _text(value, 15)
    address = ipaddress.IPv4Address(value)
    if str(address) != value or address.packed[0] == 0 or address.packed[0] >= 224:
        raise ValueError("Expected canonical unicast IPv4")
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _number(_value):
    raise ValueError("Unexpected JSON number")


def _integer(value):
    if len(value) > 5:
        raise ValueError("Invalid evidence integer")
    return int(value)


def _parse(output):
    if type(output) is bytes:
        if len(output) > MAX_INPUT_BYTES:
            raise EvidenceLimit("Evidence JSON exceeds size limit")
        try:
            text = output.decode("utf-8")
        except UnicodeError:
            raise ValueError("Invalid evidence UTF-8") from None
    else:
        text = _text(output, MAX_INPUT_BYTES)
    try:
        records = json.loads(text, object_pairs_hook=_pairs, parse_constant=_number,
                             parse_float=_number, parse_int=_integer)
    except RecursionError:
        raise ValueError("Invalid evidence nesting") from None
    if type(records) is not list:
        raise ValueError("Expected flat testssl JSON array")
    if len(records) > MAX_RAW_RECORDS:
        raise EvidenceLimit("Too many scanner records")
    return records


class TestsslPlugin(PluginJsonFormat):
    def __init__(self, *args, target=None, port=None, finding_ids=None, max_records=MAX_RECORDS, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "Testssl"
        self.name = "testssl.sh evidence"
        self.version = "3"
        self.plugin_version = "1.0.0"
        # Parsing requires caller-supplied endpoint/check binding, not autodetection.
        self.auto_load = False
        self.target = _target(target) if target is not None else None
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("Invalid evidence port")
        if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise ValueError("Invalid evidence record limit")
        if finding_ids is not None:
            if type(finding_ids) not in (list, set, frozenset) or not 1 <= len(finding_ids) <= MAX_RECORDS:
                raise ValueError("Invalid evidence finding IDs")
            for finding_id in finding_ids:
                if not _text(finding_id, 128):
                    raise ValueError("Empty evidence finding ID")
        self.port = port
        self.finding_ids = frozenset(finding_ids or [])
        self.max_records = max_records

    def processReport(self, filepath, user="faraday"):
        self.vulns_data["hosts"] = []
        super().processReport(filepath, user)

    def _parse_filename(self, filename):
        self.vulns_data["hosts"] = []
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Evidence must be a regular file")
            if metadata.st_size > MAX_INPUT_BYTES:
                raise EvidenceLimit("Evidence JSON exceeds size limit")
            self.parseOutputString(handle.read(MAX_INPUT_BYTES + 1))

    def parseOutputString(self, output):
        self.vulns_data["hosts"] = []
        for cache in (self._cache, self._hosts_cache, self._service_cache, self._vulns_cache):
            cache.clear()
        if self.target is None or self.port is None or not self.finding_ids:
            raise ValueError("Evidence requires target, port and finding IDs")
        records = _parse(output)
        evidence = []
        for record in records:
            if (type(record) is not dict or not RECORD_KEYS <= record.keys() or
                    record.keys() - RECORD_KEYS - OPTIONAL_KEYS):
                raise ValueError("Invalid testssl record fields")
            finding_id = _text(record["id"], 128)
            if not finding_id:
                raise ValueError("Empty evidence finding ID")
            finding = _text(record["finding"], 8192)
            severity = _text(record["severity"], 32).upper()
            endpoint = _text(record["ip"], 31).split("/")
            port = record["port"]
            # testssl emits this startup diagnostic before setting its endpoint.
            global_problem = (finding_id == "engine_problem" and endpoint == ["", ""]
                              and severity in {"WARN", "WARNING", "ERROR", "FATAL"}
                              and (type(port) is str and port == "443" or type(port) is int and port == 443))
            if not global_problem:
                if len(endpoint) not in (1, 2) or any(ip != self.target for ip in endpoint):
                    raise ValueError("Foreign evidence endpoint")
                if type(port) is str:
                    _text(port, 5)
                    if port != str(self.port):
                        raise ValueError("Foreign evidence port")
                elif type(port) is not int or port != self.port:
                    raise ValueError("Invalid or foreign evidence port")
            for key in record.keys() & OPTIONAL_KEYS:
                _text(record[key], 8192)
            # Filtering unrelated records can hide incomplete-check diagnostics.
            evidence.append({"name": finding_id, "desc": finding, "data": severity,
                             "severity": self.normalize_severity(severity), "type": "Vulnerability"})
            if len(evidence) > self.max_records:
                raise EvidenceLimit("Too many evidence records")
        host_id = self.createAndAddHost(self.target)
        service_id = self.createAndAddServiceToHost(host_id, "ssl", ports=self.port, protocol="tcp")
        # Base vulnerability helpers deduplicate/filter records, losing evidence.
        self.get_from_cache(service_id)["vulnerabilities"] = evidence


def createPlugin(*args, **kwargs):
    return TestsslPlugin(*args, **kwargs)
