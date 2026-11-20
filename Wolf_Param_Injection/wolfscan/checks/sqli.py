from .. import url_utils, http_client
from . import FOUND, CHECK, NOT_FOUND

KEY = "sqli"
LABEL = "SQL Injection (SQLi)"
SEVERITY = "High"
SCOPE = "param"
THRESHOLDS = (2, 1)

GENERAL = (
    "SQL injection vulnerabilities arise when user-controllable data is incorporated "
    "into database SQL queries in an unsafe manner. An attacker can supply crafted "
    "input to break out of the data context in which their input appears and interfere "
    "with the structure of the surrounding query, potentially reading or modifying "
    "data, or taking control of the database server."
)
REMEDIATION = (
    "Use parameterized queries (prepared statements) for all database access, so that "
    "the structure of the query is fixed before any item of user input is incorporated "
    "into it."
)

TIME_PAYLOAD = "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -"
ERROR_PAYLOAD = "'\""

ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sql syntax", "sqlstate", "pg_query():", "ora-00933", "ora-01756",
    "microsoft odbc", "sqlite3.operationalerror", "syntax error at or near",
]


def run(ctx):
    baseline = ctx["baseline"]

    # --- time-based probe ---
    time_url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], TIME_PAYLOAD, raw=False)
    time_resp = http_client.send(ctx["session"], time_url,
                                  timeout=http_client.boost_read_timeout(ctx["timeout"], 15),
                                  verify=ctx["verify"], proxies=ctx["proxies"])

    score = 0
    evidence_parts = []
    delay = None
    if time_resp.ok or time_resp.error == "timeout":
        delay = time_resp.elapsed - baseline.elapsed
        if delay > 4:
            score += 3
            evidence_parts.append("response delayed by %.1fs vs baseline %.1fs after a SLEEP(5) payload" %
                                   (time_resp.elapsed, baseline.elapsed))

    # --- error-based probe ---
    err_url = url_utils.build_url(ctx["url"], ctx["qs"], ctx["index"], ERROR_PAYLOAD, raw=False)
    err_resp = http_client.send(ctx["session"], err_url, timeout=ctx["timeout"],
                                 verify=ctx["verify"], proxies=ctx["proxies"])

    matched_sig = None
    if err_resp.ok:
        low = err_resp.text.lower()
        baseline_low = baseline.text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in low and sig not in baseline_low:
                matched_sig = sig
                score += 2
                evidence_parts.append("database error string %r observed after injecting a quote" % sig)
                break

    found_t, check_t = THRESHOLDS
    if score > found_t:
        status = FOUND
    elif score > check_t:
        status = CHECK
    else:
        status = NOT_FOUND

    request_used = err_url if matched_sig else time_url
    response_used = err_resp.text if matched_sig else time_resp.text

    return {"status": status, "score": score, "marker": matched_sig,
            "evidence": "; ".join(evidence_parts), "request": request_used, "response": response_used}
