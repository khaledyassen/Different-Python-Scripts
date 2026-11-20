#!/usr/bin/env python3
"""
A deliberately vulnerable local HTTP server used only to functionally test
Wolf_Param_Injection end-to-end over real sockets. Never deploy this.
"""
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qsl, unquote_plus


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output quiet

    def _get_params(self):
        parsed = urlsplit(self.path)
        return dict(parse_qsl(parsed.query, keep_blank_values=True)), parsed.path

    def do_GET(self):
        params, path = self._get_params()
        body = []
        headers_extra = []
        status = 200

        for name, raw_value in params.items():
            value = unquote_plus(raw_value)

            # XSS: reflect raw value unescaped
            if "wolf" in value and ("<" in value or "asd" in value):
                body.append("echo:" + value)

            # SQLi: error-based signature on a bare quote; time-based sleep
            if "'" in value and "SLEEP" not in value.upper():
                body.append("you have an error in your sql syntax near " + value[:5])
            if "SLEEP(5)" in value.upper():
                time.sleep(5)
                body.append("ok")

            # SSTI
            if "wolfssti" in value:
                if "123*456" in value or "123%2A456" in value:
                    body.append("wolfssti56088")

            # CRLF -> actually split into a new header if literal CRLF present
            if "\r\n" in value:
                head, _, rest = value.partition("\r\n")
                headers_extra.append(rest)
                body.append("ok")

            # Open redirect: if value looks like a URL to evil.com, 302 there
            if "evil.com" in value.lower():
                status = 302
                self.send_response(302)
                self.send_header("Location", value)
                self.end_headers()
                return

            # OS command injection: fake output for |id and timing for sleep
            if value.strip() == "|id":
                body.append("uid=33(www-data) gid=33(www-data) groups=33(www-data)")
            if "sleep 5" in value:
                time.sleep(5)
                body.append("ok")

            # LFI
            if "etc/passwd" in value or "etc%2fpasswd" in raw_value.lower():
                body.append("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")

        resp_body = ("\n".join(body) if body else "nothing interesting here").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(resp_body)))
        for h in headers_extra:
            if ":" in h:
                hname, _, hval = h.partition(":")
                self.send_header(hname.strip(), hval.strip())
        self.end_headers()
        self.wfile.write(resp_body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", "replace")
        resp_body = b"ok"
        if "<!ENTITY xxe SYSTEM" in raw_body and "&xxe;" in raw_body:
            resp_body = b"<wolf><probe>root:x:0:0:root:/root:/bin/bash</probe></wolf>"
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("vulnerable test server listening on 127.0.0.1:%d" % port)
    server.serve_forever()
