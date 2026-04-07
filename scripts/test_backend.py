#!/usr/bin/env python3
"""Minimal HTTPS backend for reverse proxy E2E testing.

Listens on port 9443 with a self-signed cert.
Responds to all requests with a JSON body containing the received headers.
"""
import http.server
import json
import ssl
import sys

PORT = 9443
CERT_DIR = "examples/reverse_proxy/certs"


class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "path": self.path,
            "method": "GET",
            "headers": dict(self.headers),
        }, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        request_body = self.rfile.read(content_length)
        body = json.dumps({
            "path": self.path,
            "method": "POST",
            "headers": dict(self.headers),
            "body": request_body.decode("utf-8", errors="replace"),
        }, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write("[backend] " + (format % args) + "\n")
        sys.stderr.flush()


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        f"{CERT_DIR}/backend_cert.pem",
        f"{CERT_DIR}/backend_key.pem",
    )
    server = http.server.HTTPServer(("127.0.0.1", PORT), TestHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"Backend listening on https://127.0.0.1:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
