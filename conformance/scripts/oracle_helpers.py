"""Oracle helpers for HTTP/1.1 cross-validation.

Wraps h11 and httptools to provide structured parse results for
three-way comparison with our Mojo parser.
"""
import h11
import httptools


def parse_with_h11(wire_bytes: bytes) -> dict:
    """Parse request bytes with h11, return structured result."""
    try:
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(wire_bytes)
        event = conn.next_event()
        if isinstance(event, h11.Request):
            headers = [
                [
                    h[0].decode("ascii", errors="replace"),
                    h[1].decode("ascii", errors="replace"),
                ]
                for h in event.headers
            ]
            # Try to get body
            body = b""
            while True:
                ev = conn.next_event()
                if isinstance(ev, h11.Data):
                    body += ev.data
                elif isinstance(ev, h11.EndOfMessage):
                    break
                elif ev is h11.NEED_DATA:
                    break
                else:
                    break
            return {
                "method": event.method.decode("ascii", errors="replace"),
                "target": event.target.decode("ascii", errors="replace"),
                "version": event.http_version.decode("ascii", errors="replace"),
                "headers": headers,
                "body": body,
                "error": None,
            }
        else:
            return {"error": f"unexpected event: {type(event).__name__}"}
    except Exception as e:
        return {"error": str(e)}


class _HttpToolsCollector:
    """Callback collector for httptools parser."""

    def __init__(self):
        self.method = None
        self.target = None
        self.version = None
        self.headers = []
        self.body = b""
        self.complete = False

    def on_url(self, url: bytes):
        self.target = url.decode("ascii", errors="replace")

    def on_header(self, name: bytes, value: bytes):
        self.headers.append(
            [
                name.decode("ascii", errors="replace"),
                value.decode("ascii", errors="replace"),
            ]
        )

    def on_body(self, body: bytes):
        self.body += body

    def on_message_complete(self):
        self.complete = True


def parse_with_httptools(wire_bytes: bytes) -> dict:
    """Parse request bytes with httptools, return structured result."""
    try:
        c = _HttpToolsCollector()
        parser = httptools.HttpRequestParser(c)
        parser.feed_data(wire_bytes)

        # httptools exposes method via get_method()
        method = parser.get_method()
        if method:
            c.method = method.decode("ascii", errors="replace")

        # httptools exposes HTTP version
        ver = parser.get_http_version()
        if ver:
            c.version = ver

        return {
            "method": c.method,
            "target": c.target,
            "version": c.version,
            "headers": c.headers,
            "body": c.body,
            "error": None,
        }
    except httptools.HttpParserError as e:
        return {"error": str(e)}
    except httptools.HttpParserCallbackError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
