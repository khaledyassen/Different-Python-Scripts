from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "ssti"
LABEL = "Server-Side Template Injection (SSTI)"
SEVERITY = "High"
SCOPE = "param"
THRESHOLDS = (1, 0)

GENERAL = (
    "Web applications commonly use template engines (Smarty, Mako, Twig, Freemarker, "
    "Jinja2, etc.) to render dynamic content. If user input is embedded into a template "
    "and not sanitized, an attacker may be able to inject template syntax that the "
    "engine evaluates, potentially leading to remote code execution."
)
REMEDIATION = (
    "Never pass raw user input into a template as if it were trusted template source - "
    "only ever pass it in as a plain data value. Where user-supplied template syntax "
    "must be rendered, do so inside a sandboxed template engine."
)

RAND = "wolfssti"
PROBE_PAYLOAD = RAND + "${123*456}" + RAND + "<%=123*567%>" + RAND + "{{123*678}}"
TWIG_PAYLOAD = "{{5*'777'}}"

EXPECTED = {
    "56088": "Java (EL / OGNL / MVEL style)",
    "69741": "Ruby (ERB style)",
    "83394": "a double-evaluated template engine",
}


def run(ctx):
    url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], PROBE_PAYLOAD, raw=False)
    resp = http_client.send(ctx["session"], url, timeout=ctx["timeout"],
                             verify=ctx["verify"], proxies=ctx["proxies"])

    if not resp.ok:
        return {"status": NOT_FOUND, "score": 0, "marker": None,
                "evidence": "request error: %s" % resp.error, "request": url, "response": ""}

    score = 0
    evidence = ""
    marker = None
    request_used = url
    response_used = resp.text

    for number, engine in EXPECTED.items():
        if (RAND + number) in resp.text:
            score = 2
            marker = number
            evidence = "arithmetic probe evaluated to %s, consistent with %s" % (number, engine)

            if number == "83394":
                # Narrow down Twig vs Jinja2 with a second, distinguishing probe.
                follow_url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], TWIG_PAYLOAD, raw=False)
                follow_resp = http_client.send(ctx["session"], follow_url, timeout=ctx["timeout"],
                                                verify=ctx["verify"], proxies=ctx["proxies"])
                if follow_resp.ok and "3885" in follow_resp.text:
                    evidence = "arithmetic probe confirms a Twig template"
                    marker = "3885"
                    request_used, response_used = follow_url, follow_resp.text
                elif follow_resp.ok and "777777777777777" in follow_resp.text:
                    evidence = "arithmetic probe confirms a Jinja2 template"
                    marker = "777777777777777"
                    request_used, response_used = follow_url, follow_resp.text
            break

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    return {"status": status, "score": score, "marker": marker,
            "evidence": evidence, "request": request_used, "response": response_used}
