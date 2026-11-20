"""
Thin wrapper around `requests` so the rest of the tool never has to deal
with exceptions, and always gets a consistent result object back - even
when the request timed out or the connection failed outright (which, for
a time-based check, is itself useful information).
"""

import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = "Wolf_Param_Injection/1.0 (+authorized security testing)"


class Result:
    def __init__(self, ok, status, text, headers, elapsed, final_url, error=None):
        self.ok = ok
        self.status = status
        self.text = text if text is not None else ""
        self.headers = headers if headers is not None else {}
        self.elapsed = elapsed
        self.final_url = final_url
        self.error = error


def boost_read_timeout(timeout, minimum):
    """Raise the READ side of a timeout to at least `minimum`, leaving any
    CONNECT timeout alone. `timeout` may be a plain float/int (requests'
    simple form) or a (connect, read) tuple (requests' explicit form, used
    by Wolf_Param_Injection.py so dead hosts fail fast on connect without
    cutting short time-based SQLi/OS-command checks that deliberately wait
    out a server-side SLEEP(5)/`sleep 5` payload)."""
    if isinstance(timeout, tuple):
        connect_timeout, read_timeout = timeout
        return (connect_timeout, max(read_timeout, minimum))
    return max(timeout, minimum)


def build_session(user_agent=None, extra_headers=None):
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent or DEFAULT_USER_AGENT})
    if extra_headers:
        session.headers.update(extra_headers)
    return session


def send(session, url, method="GET", timeout=10, allow_redirects=True,
         data=None, headers=None, verify=True, proxies=None):
    start = time.time()
    try:
        resp = session.request(
            method, url, timeout=timeout, allow_redirects=allow_redirects,
            data=data, headers=headers, verify=verify, proxies=proxies
        )
        elapsed = time.time() - start
        return Result(
            ok=True, status=resp.status_code, text=resp.text,
            headers=resp.headers, elapsed=elapsed, final_url=resp.url, error=None
        )
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        return Result(ok=False, status=None, text="", headers={}, elapsed=elapsed, final_url=url, error="timeout")
    except requests.exceptions.RequestException as e:
        elapsed = time.time() - start
        return Result(ok=False, status=None, text="", headers={}, elapsed=elapsed, final_url=url, error=str(e))
