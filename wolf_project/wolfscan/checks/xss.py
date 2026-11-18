from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "xss"
LABEL = "Cross-Site Scripting (XSS)"
SEVERITY = "High"
SCOPE = "param"
THRESHOLDS = (3, 2)  # score > 3 -> FOUND, score > 2 -> CHECK

GENERAL = (
    "Cross-site scripting vulnerabilities arise when data is copied from a request "
    "and echoed into the application's response in an unsafe way. An attacker can use "
    "the vulnerability to construct a request that, if issued by another application "
    "user, will cause JavaScript code supplied by the attacker to execute within the "
    "user's browser in the context of that user's session with the application."
)
REMEDIATION = (
    "Validate input as strictly as possible on arrival, and HTML-encode user input at "
    "any point where it is copied into application responses. All HTML metacharacters, "
    "including < > \" ' and =, should be replaced with the corresponding HTML entities."
)

FRAGMENTS = ["<", ">", "\\'asd", '\\"asd', "\\", "'\""]


def run(ctx):
    rand = ctx["marker_seed"] + "xss"
    payload = "".join(rand + f for f in FRAGMENTS)

    url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], payload, raw=False)
    resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                             verify=ctx["verify"], proxies=ctx["proxies"])

    if not resp.ok:
        return {"status": NOT_FOUND, "score": 0, "marker": None,
                "evidence": "request error: %s" % resp.error, "request": url, "response": ""}

    score = 0
    unfiltered = []
    for frag in FRAGMENTS:
        if (rand + frag) in resp.text:
            unfiltered.append(frag)
            score += 1

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    evidence = ""
    if unfiltered:
        evidence = ("Payload %r was reflected with the following characters left "
                    "un-encoded: %s" % (payload, ", ".join(unfiltered)))

    return {"status": status, "score": score, "marker": rand if unfiltered else None,
            "evidence": evidence, "request": url, "response": resp.text}
