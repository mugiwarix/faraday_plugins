# Porco validator result (parser only)

Plugin ID: `PorcoValidator` (manager lookup: `porcovalidator`). Import raw offline
`validator-result.json`, not a signed validator bundle or a scanner report.
`PluginsManager` / `ReportAnalyzer` discover this `PluginJsonFormat` plugin by
`.json` extension and its exact version-one result envelope:

```json
{
  "schema_version": 1,
  "validator_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "validator_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "runner": {"dispatcher_version": "3.9.1", "platform": "linux/amd64", "version": "1"},
  "tasks": [{
    "task_id": "cccccccccccccccccccccccccccccccc",
    "state": "COMPLETED", "stdout": "raw scanner output", "stderr": "",
    "started_at": 10, "finished_at": 11, "error": ""
  }]
}
```

Call `plugin.processReport(pathlib.Path(report_path))`, then
`plugin.get_data()["validator_result"]` to obtain the original parsed dictionary.
All evidence strings, whitespace, task ordering and values stay unchanged; JSON
serialization whitespace/escape spellings are not retained. Standard `hosts` is
empty. No hosts, services, vulnerabilities, verdicts or statuses are created.
Consumers expecting only scanner findings must explicitly handle this extension.

This plugin performs syntax and resource-bound structural checks only. It does
not interpret `state`, `error`, runner metadata, stdout/stderr, or claimed success;
`COMPLETED` is not proof of scanner completion or a true positive. It neither
executes commands nor performs network or DNS requests. There is no Porco or
cryptography dependency. Unexpected fields (including activity, target, claims,
verdict and vulnerability fields) are rejected, not trusted or converted.

**Porco remains authoritative** for Ed25519 signature verification, validator
digest binding, activity ownership, scope, expiry, revocation, task/claim binding,
evidence checks and verified status application. A parsed dictionary is untrusted
input, never authorization or verified evidence. Even malformed state/error
combinations, repeated task IDs, wrong digests and unknown runner versions can
pass structural parsing; Porco must reject them where required.

Plugin parsing accepts strict UTF-8 JSON only: duplicate keys, non-finite numbers
(including float overflow), oversized integers, invalid Unicode and trailing data
are rejected with `ValueError`. Maximum input: 8 MiB; maximum nesting: four JSON
containers; tasks: 1–1024. Task stdout/stderr are bounded to 32768/2048 UTF-8 bytes;
state/error and each runner string to 1024 bytes. IDs are lowercase hex of the
wire-contract length; timestamps are integer values in 0–253402300799. Structural
limits do not imply semantic validity.

The generic `ReportAnalyzer` probes files using its own JSON decoder before
calling any plugin. These strict limits apply to this plugin's detection and
parsing, not the manager's initial generic probe. Upload consumers must bound
input before calling `ReportAnalyzer`; they must also reject unexpected plugin
IDs and missing/non-dictionary `validator_result` data. A filename containing
`_faraday_PorcoValidator` selects the plugin directly, but never bypasses its
parsing checks.
