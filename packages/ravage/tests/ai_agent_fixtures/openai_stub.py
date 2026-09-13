from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self


class OpenAIStubHandler(BaseHTTPRequestHandler):
    actions: list[dict[str, object]]
    requests_seen: list[dict[str, object]]
    repeat_last: bool
    action_lock: threading.Lock

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        payload = json.loads(raw_body)
        with self.action_lock:
            self.requests_seen.append(payload)
            if not self.actions:
                self.send_error(503, "OpenAI stub response script exhausted")
                return
            action = (
                self.actions[0]
                if self.repeat_last and len(self.actions) == 1
                else self.actions.pop(0)
            )
        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": str(payload.get("model") or "fixture-model"),
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
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "prompt_tokens_details": {"cached_tokens": 0},
            },
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
    def __init__(
        self,
        actions: list[dict[str, object]],
        *,
        repeat_last: bool = False,
    ) -> None:
        self._handler: type[OpenAIStubHandler] = type(
            "PerTestOpenAIStubHandler",
            (OpenAIStubHandler,),
            {
                "actions": actions,
                "requests_seen": [],
                "repeat_last": repeat_last,
                "action_lock": threading.Lock(),
            },
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
