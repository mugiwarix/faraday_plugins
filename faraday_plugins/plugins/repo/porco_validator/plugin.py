"""Parse offline Porco validator results, never authenticate or apply them."""

import json
import math
import re

from faraday_plugins.plugins.plugin import PluginJsonFormat


MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_TASKS = 1024
MAX_NESTING = 4
RESULT_KEYS = {"schema_version", "validator_id", "validator_digest", "runner", "tasks"}
RUNNER_KEYS = {"dispatcher_version", "platform", "version"}
TASK_KEYS = {"task_id", "state", "stdout", "stderr", "started_at", "finished_at", "error"}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("Non-finite JSON number")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        _nonfinite(value)
    return number


def _int(value):
    # All integers in this format are small timestamps or the schema version.
    if len(value) > 20:
        raise ValueError("JSON integer exceeds limit")
    return int(value)


def _check_nesting(text):
    """Bound decoder recursion before parsing; braces inside evidence are opaque."""
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_NESTING:
                raise ValueError("Validator result nesting exceeds limit")
        elif char in "]}":
            depth -= 1


def _keys(value, expected):
    if type(value) is not dict or set(value) != expected:
        raise ValueError("Invalid validator result fields")


def _text(value, limit):
    if type(value) is not str or len(value.encode("utf-8")) > limit:
        raise ValueError("Invalid validator result string")


def _hex(value, length):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise ValueError("Invalid validator result identifier")


def _parse_result(output):
    try:
        if type(output) is bytes:
            if not output or len(output) > MAX_RESULT_BYTES:
                raise ValueError("Validator result exceeds size limit or is empty")
            text = output.decode("utf-8")
        elif type(output) is str:
            if not output or len(output) > MAX_RESULT_BYTES or len(output.encode("utf-8")) > MAX_RESULT_BYTES:
                raise ValueError("Validator result exceeds size limit or is empty")
            text = output
        else:
            raise ValueError("Expected validator result JSON bytes or text")
        _check_nesting(text)
        result = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite,
                            parse_float=_float, parse_int=_int)
        _keys(result, RESULT_KEYS)
        if type(result["schema_version"]) is not int or result["schema_version"] != 1:
            raise ValueError("Unsupported validator result schema version")
        _hex(result["validator_id"], 32)
        _hex(result["validator_digest"], 64)
        _keys(result["runner"], RUNNER_KEYS)
        for value in result["runner"].values():
            _text(value, 1024)
        tasks = result["tasks"]
        if type(tasks) is not list or not 1 <= len(tasks) <= MAX_TASKS:
            raise ValueError("Invalid validator result task count")
        for task in tasks:
            _keys(task, TASK_KEYS)
            _hex(task["task_id"], 32)
            for field, limit in (("stdout", 32768), ("stderr", 2048), ("state", 1024), ("error", 1024)):
                _text(task[field], limit)
            for field in ("started_at", "finished_at"):
                if type(task[field]) is not int or not 0 <= task[field] <= 253402300799:
                    raise ValueError("Invalid validator result timestamp")
        # No task state/error interpretation, task binding, metadata trust, or evidence parsing.
        return result
    except (UnicodeError, RecursionError, OverflowError):
        raise ValueError("Invalid validator result JSON") from None


class PorcoValidatorPlugin(PluginJsonFormat):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "PorcoValidator"
        self.name = "Porco Validator Result"
        self.version = "1"
        self.plugin_version = "1.0.0"
        self.description = "Parser-only offline validator evidence; verification belongs to Porco."
        self.json_keys = RESULT_KEYS

    def report_belongs_to(self, file_json_keys=None, **kwargs):
        if file_json_keys != self.json_keys or not super().report_belongs_to(file_json_keys=file_json_keys, **kwargs):
            return False
        try:
            self._read_result(kwargs["report_path"])
        except (KeyError, OSError, ValueError):
            return False
        return True

    @staticmethod
    def _read_result(filename):
        with open(filename, "rb") as handle:
            return _parse_result(handle.read(MAX_RESULT_BYTES + 1))

    def _parse_filename(self, filename):
        self.vulns_data.pop("validator_result", None)
        self.vulns_data["validator_result"] = self._read_result(filename)

    def parseOutputString(self, output):
        self.vulns_data.pop("validator_result", None)
        self.vulns_data["validator_result"] = _parse_result(output)


def createPlugin(*args, **kwargs):
    return PorcoValidatorPlugin(*args, **kwargs)
