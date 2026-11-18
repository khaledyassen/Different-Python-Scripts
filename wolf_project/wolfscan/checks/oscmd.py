import re

from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "oscmd"
LABEL = "OS Command Injection"
SEVERITY = "Critical"
SCOPE = "param"
THRESHOLDS = (2, 1)

GENERAL = (
    "OS command injection vulnerabilities arise when an application incorporates "
    "user-controllable data into a command passed to the operating system shell. "
    "If the data is not strictly validated, an attacker can use shell metacharacters "
    "(; | & ` $( ) ) to modify the command executed, running arbitrary commands with "
    "the privileges of the vulnerable application."
)
REMEDIATION = (
    "Avoid passing user input to an OS shell entirely; call the target functionality "
    "directly through a library API instead of shelling out. Where a command must be "
    "built dynamically, use an API that takes a list of discrete arguments rather than "
    "a single concatenated string, and strictly validate any value incorporated into it."
)

TIME_PAYLOAD = ";sleep 5;"
OUTPUT_PAYLOAD = "|id"
OUTPUT_RE = re.compile(r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+")


def run(ctx):
    baseline = ctx["baseline"]

    time_url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], TIME_PAYLOAD, raw=True)
    time_resp = http_client.send(ctx["session"], time_url, timeout=max(ctx["timeout"], 15),
                                  verify=ctx["verify"], proxies=ctx["proxies"])

    score = 0
    evidence_parts = []
    if time_resp.ok or time_resp.error == "timeout":
        delay = time_resp.elapsed - baseline.elapsed
        if delay > 4:
            score += 3
            evidence_parts.append("response delayed by %.1fs vs baseline %.1fs after a ';sleep 5;' payload" %
                                   (time_resp.elapsed, baseline.elapsed))

    out_url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], OUTPUT_PAYLOAD, raw=True)
    out_resp = http_client.send(ctx["session"], out_url, timeout=ctx["timeout"],
                                 verify=ctx["verify"], proxies=ctx["proxies"])

    marker = None
    if out_resp.ok:
        match = OUTPUT_RE.search(out_resp.text)
        if match and match.group(0) not in baseline.text:
            score += 4
            marker = match.group(0)
            evidence_parts.append("output of the id command (%r) was observed in the response" % match.group(0))

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    request_used = out_url if marker else time_url
    response_used = out_resp.text if marker else time_resp.text

    return {"status": status, "score": score, "marker": marker,
            "evidence": "; ".join(evidence_parts), "request": request_used, "response": response_used}
