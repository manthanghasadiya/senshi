"""
CallbackServer — lightweight HTTP server for SSRF/XXE/RCE detection.

Starts a local HTTP server that listens for callbacks from injected payloads.
Each payload gets a unique token, so we can correlate callbacks to findings.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse, parse_qs

from senshi.utils.logger import get_logger

logger = get_logger("senshi.oob.callback_server")


class CallbackServer:
    """
    Lightweight HTTP callback receiver for OOB vulnerability detection.

    Used for SSRF, XXE, RCE, and blind injection testing.
    Each payload includes a unique callback token.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9999) -> None:
        self.host = host
        self.port = port
        self.callbacks: dict[str, list[dict[str, Any]]] = {}
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def generate_token(self) -> str:
        """Generate a unique callback token."""
        token = secrets.token_hex(8)
        self.callbacks[token] = []
        return token

    @property
    def callback_url(self) -> str:
        """Base callback URL."""
        return f"http://{self._get_public_host()}:{self.port}"

    def get_payload_url(self, token: str, path: str = "/callback") -> str:
        """Get the callback URL for a specific payload token."""
        return f"{self.callback_url}{path}?token={token}"

    def start(self) -> None:
        """Start the callback server in a background thread."""
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._handle_request()

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode() if content_length else ""
                self._handle_request(body=body)

            def do_PUT(self) -> None:
                self.do_POST()

            def _handle_request(self, body: str = "") -> None:
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                token = params.get("token", [None])[0]

                callback_data = {
                    "timestamp": time.time(),
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "source_ip": self.client_address[0],
                    "body": body,
                }

                if token and token in server_ref.callbacks:
                    server_ref.callbacks[token].append(callback_data)
                    logger.info(f"Callback received for token {token} from {self.client_address[0]}")
                else:
                    logger.debug(f"Unknown callback: {self.path}")

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress default logging

        self._server = HTTPServer((self.host, self.port), Handler)
        self._running = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Callback server started on {self.host}:{self.port}")

    def stop(self) -> None:
        """Stop the callback server."""
        if self._server:
            self._server.shutdown()
            self._running = False
            logger.info("Callback server stopped")

    def check_callback(self, token: str) -> list[dict[str, Any]]:
        """Check if a callback was received for a token."""
        return self.callbacks.get(token, [])

    def has_callback(self, token: str) -> bool:
        """Check if any callback was received."""
        return len(self.callbacks.get(token, [])) > 0

    async def wait_for_callback(self, token: str, timeout: float = 10.0) -> bool:
        """Wait for a callback with timeout."""
        start = time.time()
        while time.time() - start < timeout:
            if self.has_callback(token):
                return True
            await asyncio.sleep(0.5)
        return False

    @staticmethod
    def _get_public_host() -> str:
        """Try to get the public IP/hostname."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
