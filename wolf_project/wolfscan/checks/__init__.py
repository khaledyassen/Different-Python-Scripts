"""
Every vulnerability class Wolf_Param_Injection tests for is one module in
this package. A module exposes:

    KEY           short id, used on the --checks command line flag
    LABEL         human readable name
    SEVERITY      shown in the report
    SCOPE         "param"  - tested once per query-string parameter
                  "body"   - tested once per URL (body-based, e.g. XXE)
    GENERAL       generic write-up of the vulnerability class
    REMEDIATION   generic remediation advice
    THRESHOLDS    (found_threshold, check_threshold) - score has to be
                  strictly greater than these to count as Found / Check
    run(ctx)      -> dict(status, score, marker, evidence, request, response)

`ctx` is a plain dict built by the scanner; see scanner.py for its keys.

To add a new check: write a module with the above, then add it to the
CHECKS list below. Nothing else in the tool needs to change.
"""

FOUND = "FOUND"
CHECK = "CHECK MANUALLY"
NOT_FOUND = "NOT FOUND"
ERROR = "ERROR"

from . import xss
from . import sqli
from . import ssti
from . import crlf
from . import open_redirect
from . import xxe
from . import oscmd
from . import lfi

CHECKS = [xss, sqli, ssti, crlf, open_redirect, xxe, oscmd, lfi]
CHECKS_BY_KEY = {c.KEY: c for c in CHECKS}


def status_from_score(module, score):
    found_t, check_t = module.THRESHOLDS
    if score > found_t:
        return FOUND
    if score > check_t:
        return CHECK
    return NOT_FOUND
