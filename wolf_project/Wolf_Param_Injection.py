#!/usr/bin/env python3
"""
Wolf_Param_Injection - standalone command-line parameter-injection scanner.

Reads a text file of URLs (one per line, each with its own query-string
parameters), and for every parameter tests for:

    XSS, SQL Injection, SSTI, CRLF Injection, Open Redirect,
    XXE, OS Command Injection, LFI/LFD

No Burp Suite / browser / proxy is involved - this talks straight to the
target over plain HTTP(S) using `requests`.

IMPORTANT: only ever point this at systems you are authorized to test.
"""

import argparse
import sys

from wolfscan import http_client, reporter, scanner
from wolfscan.checks import CHECKS_BY_KEY, CHECKS

BANNER = r"""
 __        __    _  __   ____                             ___       _           _   _
 \ \      / /__ | |/ _| |  _ \ __ _ _ __ __ _ _ __ ___    |_ _|_ __ (_) ___  ___| |_(_) ___  _ __
  \ \ /\ / / _ \| | |_  | |_) / _` | '__/ _` | '_ ` _ \    | || '_ \| |/ _ \/ __| __| |/ _ \| '_ \
   \ V  V / (_) | |  _| |  __/ (_| | | | (_| | | | | | |   | || | | | |  __/ (__| |_| | (_) | | | |
    \_/\_/ \___/|_|_|   |_|   \__,_|_|  \__,_|_| |_| |_|  |___|_| |_|_|\___|\___|\__|_|\___/|_| |_|

  Parameter injection scanner - authorized security testing only.
"""


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="wolf.py",
        description="Wolf_Param_Injection - scan a list of URLs with parameters for common injection vulnerabilities.",
    )
    p.add_argument("-f", "--file", required=True, help="path to a text file containing one URL per line")
    p.add_argument("-c", "--checks", default="all",
                    help="comma-separated list of checks to run: %s (default: all)" % ",".join(CHECKS_BY_KEY.keys()))
    p.add_argument("-o", "--output", help="write a full JSON report to this path")
    p.add_argument("--csv", help="write a full CSV report to this path")
    p.add_argument("-t", "--timeout", type=float, default=10, help="per-request timeout in seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0, help="delay in seconds between requests (default: 0)")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--proxy", help="optional HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--user-agent", help="custom User-Agent header")
    p.add_argument("-H", "--header", action="append", default=[],
                    help="extra request header 'Name: Value', may be given multiple times")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colored output")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the final summary, not per-URL detail")
    return p.parse_args(argv)


def load_urls(path):
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def resolve_checks(spec):
    if spec.strip().lower() == "all":
        return list(CHECKS_BY_KEY.keys())
    keys = [k.strip() for k in spec.split(",") if k.strip()]
    unknown = [k for k in keys if k not in CHECKS_BY_KEY]
    if unknown:
        raise SystemExit("Unknown check(s): %s. Valid checks: %s" %
                          (", ".join(unknown), ", ".join(CHECKS_BY_KEY.keys())))
    return keys


def parse_headers(header_args):
    headers = {}
    for h in header_args:
        if ":" not in h:
            raise SystemExit("--header must be 'Name: Value', got: %r" % h)
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    color = reporter.Colorizer(enabled=not args.no_color and sys.stdout.isatty())

    if not args.no_banner:
        print(color(BANNER, reporter.CYAN))
        print(color("  Only scan systems you are authorized to test.\n", reporter.YELLOW))

    try:
        urls = load_urls(args.file)
    except OSError as e:
        print("Could not read %s: %s" % (args.file, e), file=sys.stderr)
        return 1

    if not urls:
        print("No URLs found in %s" % args.file, file=sys.stderr)
        return 1

    check_keys = resolve_checks(args.checks)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    extra_headers = parse_headers(args.header)
    session = http_client.build_session(user_agent=args.user_agent, extra_headers=extra_headers)

    print("Loaded %d URL(s) from %s" % (len(urls), args.file))
    print("Checks enabled: %s" % ", ".join(CHECKS_BY_KEY[k].LABEL for k in check_keys))
    print()

    all_results = []
    for i, url in enumerate(urls, 1):
        if not args.quiet:
            print(color("[%d/%d] scanning %s" % (i, len(urls), url), reporter.BOLD))
        result = scanner.scan_url(
            url, session, check_keys, timeout=args.timeout,
            verify=not args.insecure, proxies=proxies, delay=args.delay,
        )
        all_results.append(result)
        if not args.quiet:
            reporter.print_url_result(result, color)

    reporter.print_summary(all_results, color)

    if args.output:
        reporter.save_json(all_results, args.output)
        print("\nJSON report written to %s" % args.output)
    if args.csv:
        reporter.save_csv(all_results, args.csv)
        print("CSV report written to %s" % args.csv)

    return 0


if __name__ == "__main__":
    sys.exit(main())
