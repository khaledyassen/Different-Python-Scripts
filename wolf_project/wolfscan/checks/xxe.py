from .. import http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "xxe"
LABEL = "XML External Entity (XXE)"
SEVERITY = "High"
SCOPE = "body"  # tested once per URL, not once per query-string parameter
THRESHOLDS = (2, 1)

GENERAL = (
    "XML External Entity (XXE) injection vulnerabilities arise when an application "
    "parses attacker-supplied XML without disabling the resolution of external "
    "entities. An attacker can define a custom external entity referencing a local "
    "file:// path and have the parser read and disclose its contents, or make "
    "outbound network requests (SSRF)."
)
REMEDIATION = (
    "Disable DTD processing and external entity resolution entirely in the XML "
    "parser being used. Prefer a data format that does not support entities (such "
    "as JSON) wherever XML support is not strictly required."
)

XML_ERROR_SIGNATURES = [
    "doctype is not allowed", "external entity", "xmlsyntaxerror",
    "simplexmlelement", "failed to load external entity", "dtd is prohibited",
    "parserconfigurationexception",
]

PROBE_BODY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE wolf [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<wolf><probe>&xxe;</probe></wolf>"
)


def run(ctx):
    """
    Query-string parameters tell us nothing about whether an endpoint also
    accepts an XML body, so this check just POSTs a self-contained XXE probe
    document straight at the URL (unmodified query string and all) and looks
    for /etc/passwd content or an XML-parser error in the response. Many
    frameworks route the same endpoint for GET and POST, which is exactly
    the case this is aimed at; if the endpoint genuinely never accepts XML
    the probe will simply be ignored or rejected.
    """
    url = ctx["url"]
    resp = http_client.send(
        ctx["session"], url, method="POST", timeout=ctx["timeout"],
        data=PROBE_BODY.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
        verify=ctx["verify"], proxies=ctx["proxies"],
    )

    if not resp.ok:
        return {"status": NOT_FOUND, "score": 0, "marker": None,
                "evidence": "request error: %s" % resp.error, "request": url, "response": ""}

    score = 0
    evidence = ""
    marker = None

    if "root:" in resp.text and ":0:0:" in resp.text:
        score = 4
        marker = "root:"
        evidence = "an external entity referencing file:///etc/passwd was processed and its contents leaked into the response"
    else:
        low = resp.text.lower()
        for sig in XML_ERROR_SIGNATURES:
            if sig in low:
                score = 2
                marker = sig
                evidence = "an XML-parser error (%r) suggests the DOCTYPE/entity was at least partially processed" % sig
                break

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    return {"status": status, "score": score, "marker": marker,
            "evidence": evidence, "request": url + "  [POST, Content-Type: application/xml]",
            "response": resp.text}
