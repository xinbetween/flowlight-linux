#!/usr/bin/env python3
"""A model that is not a model, for the smoke test.

Speaks the OpenAI chat-completions shape well enough to exercise the whole Ask loop against a running daemon:
the first request is answered with a tool call, and the request that carries the tool's result is answered with
a sentence quoting it. Every body it receives is written down, so the test can assert what left the daemon.

Not a mock in the test's own process. The point is to go through the real provider code, the real socket and
the real query runner, because every interesting failure in this feature lives between those.
"""

import json
import socket
import sys
import threading

log = sys.argv[1]
ready = sys.argv[2]

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(8)
with open(ready, "w") as file:
    file.write(str(listener.getsockname()[1]))


def reply(body):
    payload = json.dumps(body).encode()
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(payload)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + payload
    )


def answer(request):
    """A tool call first, an answer once the tool has answered."""
    messages = request.get("messages", [])
    results = [message for message in messages if message.get("role") == "tool"]
    if not results:
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "runQuery",
                                    "arguments": json.dumps({"query": "totals", "from": "24h"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
    totals = json.loads(results[0].get("content", "{}"))
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "FLOWLIGHT-SAW %s requests in %s."
                    % (totals.get("requests", "?"), totals.get("window", "?")),
                }
            }
        ]
    }


def serve(client):
    with client:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(rest) < length:
            chunk = client.recv(65536)
            if not chunk:
                break
            rest += chunk
        with open(log, "a") as file:
            file.write(rest.decode("utf-8", "replace") + "\n--- end of body ---\n")
        try:
            request = json.loads(rest)
        except ValueError:
            client.sendall(reply({"error": "not json"}))
            return
        client.sendall(reply(answer(request)))


while True:
    client, _ = listener.accept()
    threading.Thread(target=serve, args=(client,), daemon=True).start()
