from __future__ import annotations

from ravage.runtime import ExternalToolRuntime


def test_requests_shim_cookie_jar_supports_mapping_helpers() -> None:
    runtime = ExternalToolRuntime()
    try:
        result = runtime.run_python(
            code=(
                "import requests\n"
                "session = requests.Session()\n"
                "session.cookies.set('session', 'abc')\n"
                "print(session.cookies.get('session'))\n"
                "session.cookies.update({'role': 'user'})\n"
                "print(session.cookies.get_dict()['role'])\n"
            ),
            target_url="http://127.0.0.1:8765",
        )
    finally:
        runtime.close()

    assert result.ok
    assert result.stdout.splitlines() == ["abc", "user"]


def test_requests_shim_encodes_repeated_form_fields() -> None:
    runtime = ExternalToolRuntime()
    try:
        result = runtime.run_python(
            code=(
                "import requests\n"
                "class FakeResponse:\n"
                "    status = 200\n"
                "    headers = {}\n"
                "    def read(self): return b'ok'\n"
                "    def geturl(self): return 'http://127.0.0.1:8765/login'\n"
                "class FakeOpener:\n"
                "    def open(self, request, timeout=None):\n"
                "        print(request.data.decode())\n"
                "        print(request.headers.get('Content-type'))\n"
                "        return FakeResponse()\n"
                "session = requests.Session()\n"
                "session._opener = FakeOpener()\n"
                "session.post('http://127.0.0.1:8765/login', "
                "data=[('username','test'),('username','admin'),('password','test')])\n"
            ),
            target_url="http://127.0.0.1:8765",
        )
    finally:
        runtime.close()

    assert result.ok
    assert "username=test&username=admin&password=test" in result.stdout
    assert "application/x-www-form-urlencoded" in result.stdout
