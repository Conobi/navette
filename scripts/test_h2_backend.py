#!/usr/bin/env python3
"""Minimal HTTPS HTTP/2 backend for reverse proxy E2E testing.

Listens on port 9444 with a self-signed cert and ALPN h2.
Responds to all requests with a JSON body containing the received
method, path, headers, and body.
"""
import json
import socket
import ssl
import sys

import h2.config
import h2.connection
import h2.events

PORT = 9444
CERT_DIR = "examples/reverse_proxy/certs"


def handle_connection(client_sock):
    """Handle a single HTTP/2 connection."""
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    client_sock.sendall(conn.data_to_send())

    # Per-stream state: stream_id -> {method, path, headers, body}
    streams = {}

    while True:
        try:
            data = client_sock.recv(65535)
        except (ConnectionResetError, OSError):
            break
        if not data:
            break

        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                method = ""
                path = ""
                headers = {}
                for name, value in event.headers:
                    name_str = name if isinstance(name, str) else name.decode("ascii", errors="replace")
                    value_str = value if isinstance(value, str) else value.decode("ascii", errors="replace")
                    if name_str == ":method":
                        method = value_str
                    elif name_str == ":path":
                        path = value_str
                    elif not name_str.startswith(":"):
                        headers[name_str] = value_str
                streams[event.stream_id] = {
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": b"",
                }

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in streams:
                    streams[event.stream_id]["body"] += event.data
                conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id not in streams:
                    continue
                stream = streams.pop(event.stream_id)
                response_body = {
                    "path": stream["path"],
                    "method": stream["method"],
                    "headers": stream["headers"],
                }
                if stream["body"]:
                    response_body["body"] = stream["body"].decode(
                        "utf-8", errors="replace"
                    )
                body_bytes = json.dumps(response_body, indent=2).encode("utf-8")
                conn.send_headers(
                    event.stream_id,
                    [
                        (":status", "200"),
                        ("content-type", "application/json"),
                        ("content-length", str(len(body_bytes))),
                    ],
                )
                conn.send_data(event.stream_id, body_bytes, end_stream=True)

            elif isinstance(event, h2.events.WindowUpdated):
                pass

        try:
            outgoing = conn.data_to_send()
            if outgoing:
                client_sock.sendall(outgoing)
        except (ConnectionResetError, BrokenPipeError, OSError):
            break


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        f"{CERT_DIR}/backend_cert.pem",
        f"{CERT_DIR}/backend_key.pem",
    )
    ctx.set_alpn_protocols(["h2"])

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", PORT))
    server_sock.listen(5)
    print(f"H2 backend listening on https://127.0.0.1:{PORT}", flush=True)

    try:
        while True:
            client_sock, addr = server_sock.accept()
            try:
                tls_sock = ctx.wrap_socket(client_sock, server_side=True)
                sys.stderr.write(f"[h2-backend] connection from {addr}\n")
                sys.stderr.flush()
                handle_connection(tls_sock)
            except ssl.SSLError as e:
                sys.stderr.write(f"[h2-backend] TLS error: {e}\n")
                sys.stderr.flush()
            except Exception as e:
                sys.stderr.write(f"[h2-backend] error: {e}\n")
                sys.stderr.flush()
            finally:
                try:
                    client_sock.close()
                except OSError:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
