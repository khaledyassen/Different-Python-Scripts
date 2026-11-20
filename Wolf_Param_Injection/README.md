# Wolf_Param_Injection

A standalone, terminal-based parameter-injection scanner. It is **not** a
Burp Suite extension and has no dependency on Burp - it talks straight to
the target over plain HTTP(S) using the [`requests`](https://pypi.org/project/requests/)
library, and can be run from any machine with Python 3.

Give it a text file of URLs (each with its own query-string parameters)
and it will test every parameter on every URL for:

| Check                              | Idea                                                               |
|-------------------------------------|---------------------------------------------------------------------|
| Cross-Site Scripting (XSS)         | reflects a marker string with `< > ' " \` fragments, checks which come back un-encoded |
| SQL Injection (SQLi)               | time-based (`SLEEP(5)`) + error-based (bare quote) probes          |
| Server-Side Template Injection     | arithmetic template expressions (`${123*456}`, `{{123*678}}`, ...) |
| CRLF Injection                     | injects `%0d%0a` + a marker header, checks if it becomes a real response header |
| **Open Redirect**                  | points the parameter at `evil.com` and checks the `Location` header / final URL |
| XML External Entity (XXE)          | POSTs an XML body with an external entity referencing `/etc/passwd` |
| OS Command Injection               | time-based (`;sleep 5;`) + output-based (`\|id` → `uid=...gid=...`) |
| Local File Inclusion / Disclosure  | path-traversal payloads aimed at `/etc/passwd` and `win.ini`       |

Every finding is reported as **FOUND**, **CHECK MANUALLY**, or **NOT FOUND**,
with the exact payload, evidence, and request URL used - the same idea as
the original Trishul Burp extension this tool grew out of, just running
as its own CLI program instead of inside Burp.

> ⚠️ **Only ever point this at systems you are authorized to test.**

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.7+.

## Usage

```bash
python3 wolf.py -f urls.txt
```

`urls.txt` is a plain text file, one URL per line (see `sample_urls.txt`).
Lines starting with `#` and blank lines are ignored. Each parameter in
each URL's query string is tested individually; the other parameters on
that URL keep their original values while one is swapped out for a
payload at a time.

### Options

```
-f, --file FILE       path to a text file containing one URL per line (required)
-c, --checks LIST     comma-separated checks to run, e.g. "xss,sqli,openredirect"
                       (default: all). Valid keys: xss, sqli, ssti, crlf,
                       openredirect, xxe, oscmd, lfi
-o, --output FILE     write a full JSON report to this path
    --csv FILE        write a full CSV report to this path
-t, --timeout SECONDS per-request timeout (default: 10)
    --delay SECONDS   delay between requests, to go easier on the target (default: 0)
    --insecure        do not verify TLS certificates
    --proxy URL       send all traffic through an HTTP(S) proxy, e.g. http://127.0.0.1:8080
    --user-agent STR  custom User-Agent header
-H, --header "N: V"   extra request header, may be given multiple times
    --no-color        disable ANSI colored output
    --no-banner       suppress the startup banner
-q, --quiet           only print the final summary table, not per-URL detail
```

### Examples

Run everything, print to the terminal, and also save a JSON report:

```bash
python3 wolf.py -f urls.txt -o report.json
```

Fast Scan
```bash
python3 Wolf_Param_Injection.py -f urls.txt -w 30 --retries 2 --connect-timeout 4 -t 8 --max-url-time 25 --checkpoint done.txt --autosave-every 50 -o report.json
```

Only test for XSS and Open Redirect, through a local proxy:

```bash
python3 wolf.py -f urls.txt -c xss,openredirect --proxy http://127.0.0.1:8080
```

Quiet mode (summary table only) with a CSV report, and a 0.5s delay between
requests so you don't hammer the target:

```bash
python3 wolf.py -f urls.txt -q --csv report.csv --delay 0.5
```

## How detection works

Every check follows the same idea:

1. Take the parameter's current value and replace it with a payload (every
   other parameter on the URL is left exactly as it was).
2. Send the request and compare the response against a **baseline**
   request (the original, unmodified URL) fetched once per URL, so that
   content or timing that is already present before any payload is sent
   never gets flagged.
3. Score the result (reflected markers, error strings, timing deltas,
   redirect targets, leaked file content, etc.) and classify it as
   `FOUND`, `CHECK MANUALLY`, or `NOT FOUND` against a fixed threshold.

XXE is the one exception: since the input file only gives GET-style
URLs with query parameters, there's no indication of an XML body to
tamper with. Instead, the XXE check is tested once per URL (not once per
parameter): it POSTs a self-contained XML document carrying the external
entity straight at the URL, on the theory that many frameworks route the
same endpoint for GET and POST. If the endpoint never accepts XML, the
probe is simply ignored and it reports "Not Found".

## Project layout

```
wolf.py                    CLI entry point
wolfscan/
  http_client.py           thin wrapper around requests, uniform result object
  url_utils.py              query-string parsing / payload-insertion helpers
  scanner.py                orchestration: baseline fetch, runs each check per parameter
  reporter.py                console output + JSON/CSV export
  checks/
    xss.py, sqli.py, ssti.py, crlf.py, open_redirect.py,
    xxe.py, oscmd.py, lfi.py      one module per vulnerability class
sample_urls.txt            example input file
requirements.txt
```

To add a new check: write a module in `wolfscan/checks/` exposing `KEY`,
`LABEL`, `SEVERITY`, `SCOPE` ("param" or "body"), `THRESHOLDS`, `GENERAL`,
`REMEDIATION`, and a `run(ctx)` function, then add it to the `CHECKS` list
in `wolfscan/checks/__init__.py`. The CLI's `--checks` flag, the table
columns in the report, and the summary counts all pick it up automatically.

## Testing it against something safe first

`tests/vuln_test_server.py` is a small, deliberately-vulnerable local HTTP
server (no real shell commands are ever executed) used to sanity-check the
scanner end-to-end before pointing it at a real target:

```bash
python3 tests/vuln_test_server.py 8765 &
echo "http://127.0.0.1:8765/page?q=hello&redirect=/account" > /tmp/local.txt
python3 wolf.py -f /tmp/local.txt
```

Every check should come back `FOUND` against it, and `NOT FOUND` against
any ordinary, non-vulnerable site.

## Disclaimer

This tool actively sends exploit-style payloads (including ones that
intentionally try to redirect to `evil.com`, read `/etc/passwd`, or run
`sleep`/`id` through a shell) to every URL you give it. Use it only
against systems you own or have explicit written authorization to test.
