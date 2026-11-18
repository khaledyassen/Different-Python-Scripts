from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "openredirect"
LABEL = "Open Redirect"
SEVERITY = "Medium"
SCOPE = "param"
THRESHOLDS = (2, 1)

GENERAL = (
    "Open redirect vulnerabilities arise when an application takes a user-controllable "
    "value (often a 'next', 'url', 'return', or 'redirect' parameter) and uses it, "
    "unvalidated, as the destination of an HTTP redirect. An attacker can craft a link "
    "that points at the trusted site but redirects the victim on to an attacker-"
    "controlled domain, which is commonly abused in phishing campaigns."
)
REMEDIATION = (
    "Avoid redirecting to a URL taken directly from user input. Where this is "
    "unavoidable, validate the destination against an allow-list of known-good paths "
    "or domains, and reject (rather than silently correct) anything that does not "
    "match. Relative paths only, resolved against the current host, are the safest "
    "option."
)

CANARY_DOMAIN = "evil.com"
PAYLOADS = [
    "https://" + CANARY_DOMAIN,
    "http://" + CANARY_DOMAIN,
    "//" + CANARY_DOMAIN,
    "https:" + CANARY_DOMAIN,
    "https://" + CANARY_DOMAIN + "@legituser",
    "/%09/" + CANARY_DOMAIN,
]


def run(ctx):
    baseline = ctx["baseline"]
    baseline_has_canary = CANARY_DOMAIN in baseline.text.lower()

    score = 0
    evidence = ""
    marker = None
    request_used = None
    response_used = ""

    for payload in PAYLOADS:
        url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], payload, raw=False)
        resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                                 allow_redirects=False, verify=ctx["verify"], proxies=ctx["proxies"])
        if request_used is None:
            request_used = url
            response_used = resp.text if resp.ok else ""

        if not resp.ok:
            continue

        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if resp.status in (301, 302, 303, 307, 308) and CANARY_DOMAIN in location.lower():
            score = 4
            marker = location
            evidence = ("payload %r produced a %s redirect with Location: %s" %
                        (payload, resp.status, location))
            request_used, response_used = url, resp.text
            break

        # Also follow redirects (small hop limit via requests default) to catch
        # client-side / meta-refresh style redirects that `requests` itself
        # won't have already followed above.
        follow_resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                                        allow_redirects=True, verify=ctx["verify"], proxies=ctx["proxies"])
        if follow_resp.ok and CANARY_DOMAIN in follow_resp.final_url.lower() and follow_resp.history:
            score = 4
            marker = follow_resp.final_url
            evidence = "payload %r was followed all the way to %s" % (payload, follow_resp.final_url)
            request_used, response_used = url, follow_resp.text
            break

        if resp.ok and CANARY_DOMAIN in resp.text.lower() and not baseline_has_canary and score < 2:
            score = 2
            marker = CANARY_DOMAIN
            evidence = ("payload %r was reflected in the response body (e.g. inside a link or "
                        "meta-refresh) but no server-side redirect was observed; check manually" % payload)
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
