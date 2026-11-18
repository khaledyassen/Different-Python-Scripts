import random
import string
import time

from . import http_client, url_utils
from .checks import CHECKS_BY_KEY, NOT_FOUND


def random_seed(n=6):
    return "wolf" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class ParamResult:
    def __init__(self, param_name, check_key, outcome):
        self.param_name = param_name
        self.check_key = check_key
        self.status = outcome["status"]
        self.score = outcome["score"]
        self.marker = outcome.get("marker")
        self.evidence = outcome.get("evidence", "")
        self.request = outcome.get("request", "")
        self.response = outcome.get("response", "")


class UrlScanResult:
    def __init__(self, url):
        self.url = url
        self.skipped_reason = None
        self.baseline = None
        self.results = []  # list[ParamResult]

    def add(self, param_name, check_key, outcome):
        self.results.append(ParamResult(param_name, check_key, outcome))


def fetch_baseline(session, url, timeout, verify, proxies):
    return http_client.send(session, url, timeout=timeout, verify=verify, proxies=proxies)


def scan_url(url, session, enabled_check_keys, timeout=10, verify=True, proxies=None, delay=0):
    """Run every enabled check against every query-string parameter of `url`,
    plus any body-scoped checks (currently just XXE) once for the whole URL.
    Returns a UrlScanResult."""

    result = UrlScanResult(url)

    if not url_utils.has_scheme(url):
        result.skipped_reason = "no scheme/host (expected e.g. http://host/path?param=value)"
        return result

    qs = url_utils.parse_query(url)
    body_checks = [k for k in enabled_check_keys if CHECKS_BY_KEY[k].SCOPE == "body"]
    param_checks = [k for k in enabled_check_keys if CHECKS_BY_KEY[k].SCOPE == "param"]

    if not qs and not body_checks:
        result.skipped_reason = "no query-string parameters found"
        return result

    baseline = fetch_baseline(session, url, timeout, verify, proxies)
    result.baseline = baseline
    if not baseline.ok:
        # A dead/unreachable baseline doesn't block body-scoped checks (they
        # make their own fresh request), but per-parameter checks that rely
        # on comparing against it are skipped.
        if not body_checks:
            result.skipped_reason = "baseline request failed: %s" % baseline.error
            return result

    marker_seed = random_seed()

    if qs:
        for index, (name, value) in enumerate(qs):
            for key in param_checks:
                module = CHECKS_BY_KEY[key]
                ctx = {
                    "url": url, "qs": qs, "index": index, "param_name": name,
                    "param_value": value, "session": session, "timeout": timeout,
                    "verify": verify, "proxies": proxies, "baseline": baseline,
                    "marker_seed": marker_seed,
                }
                try:
                    outcome = module.run(ctx)
                except Exception as e:
                    outcome = {"status": NOT_FOUND, "score": 0, "marker": None,
                               "evidence": "internal error running check: %s" % e,
                               "request": url, "response": ""}
                result.add(name, key, outcome)
                if delay:
                    time.sleep(delay)

    for key in body_checks:
        module = CHECKS_BY_KEY[key]
        ctx = {
            "url": url, "qs": qs, "index": None, "param_name": "(request body)",
            "param_value": None, "session": session, "timeout": timeout,
            "verify": verify, "proxies": proxies, "baseline": baseline,
            "marker_seed": marker_seed,
        }
        try:
            outcome = module.run(ctx)
        except Exception as e:
            outcome = {"status": NOT_FOUND, "score": 0, "marker": None,
                       "evidence": "internal error running check: %s" % e,
                       "request": url, "response": ""}
        result.add("(request body)", key, outcome)
        if delay:
            time.sleep(delay)

    return result
