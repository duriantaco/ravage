from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self


class OpenAIStubHandler(BaseHTTPRequestHandler):
    actions: list[dict[str, object]]
    requests_seen: list[dict[str, object]]

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        payload = json.loads(raw_body)
        self.requests_seen.append(payload)
        action = self.actions.pop(0)
        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(action),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return


class OpenAIStubServer:
    def __init__(self, actions: list[dict[str, object]]) -> None:
        self._handler: type[OpenAIStubHandler] = type(
            "PerTestOpenAIStubHandler",
            (OpenAIStubHandler,),
            {"actions": actions, "requests_seen": []},
        )
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    @property
    def requests_seen(self) -> list[dict[str, object]]:
        return self._handler.requests_seen
