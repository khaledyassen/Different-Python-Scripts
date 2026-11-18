from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "crlf"
LABEL = "CRLF Injection"
SEVERITY = "Medium"
SCOPE = "param"
THRESHOLDS = (2, 1)

GENERAL = (
    "CRLF (Carriage Return Line Feed) injection vulnerabilities arise when user input "
    "containing unescaped \\r\\n sequences reaches an HTTP response header. If an "
    "attacker can inject a CRLF sequence followed by their own header, they can split "
    "the response, inject arbitrary response headers or cookies, poison a cache, or "
    "terminate the header section early and write their own body (leading to reflected "
    "XSS via response splitting)."
)
REMEDIATION = (
    "Never place user-controllable data directly into a response header, redirect "
    "Location, or Set-Cookie value without stripping or encoding CR (%0D) and LF (%0A). "
    "Use framework APIs for setting headers/cookies/redirects instead of concatenating "
    "raw strings."
)

RAND = "wolfcrlf"
HEADER_NAME = "X-Wolf-CRLF"
PAYLOAD = "%s%%0d%%0a%s:%%20injected" % (RAND, HEADER_NAME)


def run(ctx):
    url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], PAYLOAD, raw=True)
    resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                             allow_redirects=False, verify=ctx["verify"], proxies=ctx["proxies"])

    if not resp.ok:
        return {"status": NOT_FOUND, "score": 0, "marker": None,
                "evidence": "request error: %s" % resp.error, "request": url, "response": ""}

    score = 0
    evidence = ""
    marker = None

    header_found = any(HEADER_NAME.lower() == h.lower() for h in resp.headers.keys())
    if header_found:
        score = 4
        marker = HEADER_NAME
        evidence = "the injected %s header came back as a genuine, separate response header" % HEADER_NAME
    elif (RAND + "\r\n" + HEADER_NAME) in resp.text or (RAND + "%0d%0a" + HEADER_NAME) in resp.text:
        score = 2
        marker = RAND
        evidence = "the raw CR/LF sequence was reflected unencoded in the response body"

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    return {"status": status, "score": score, "marker": marker,
            "evidence": evidence, "request": url, "response": resp.text}
