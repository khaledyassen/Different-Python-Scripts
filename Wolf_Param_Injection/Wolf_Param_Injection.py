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
import concurrent.futures
import json
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from wolfscan import http_client, reporter, scanner
from wolfscan.checks import CHECKS_BY_KEY, CHECKS
from wolfscan.scanner import UrlScanResult

BANNER = r"""
 __        __    _  __   ____                             ___       _           _   _
 \ \      / /__ | |/ _| |  _ \ __ _ _ __ __ _ _ __ ___    |_ _|_ __ (_) ___  ___| |_(_) ___  _ __
  \ \ /\ / / _ \| | |_  | |_) / _` | '__/ _` | '_ ` _ \    | || '_ \| |/ _ \/ __| __| |/ _ \| '_ \
   \ V  V / (_) | |  _| |  __/ (_| | | | (_| | | | | | |   | || | | | |  __/ (__| |_| | (_) | | | |
    \_/\_/ \___/|_|_|   |_|   \__,_|_|  \__,_|_| |_| |_|  |___|_| |_|_|\___|\___|\__|_|\___/|_| |_|

  Parameter injection scanner - authorized security testing only.
"""


def skipped_result(url, reason):
    """A UrlScanResult that never got real findings - same mechanism the
    scanner itself already uses for 'no query params' / 'dead baseline'
    (reporter.py treats any .skipped_reason the same way, so this is a
    real, fully-compatible result object, not a guess)."""
    r = UrlScanResult(url)
    r.skipped_reason = reason
    return r


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
    p.add_argument("-t", "--timeout", type=float, default=10,
                    help="per-request READ timeout in seconds (default: 10)")
    p.add_argument("--connect-timeout", type=float, default=None,
                    help="per-request CONNECT timeout in seconds, separate from --timeout "
                         "(default: min(5, --timeout), so a dead/unreachable host fails fast "
                         "instead of hanging for the full read timeout on every param/payload)")
    p.add_argument("--delay", type=float, default=0, help="delay in seconds between requests (default: 0)")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--proxy", help="optional HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--user-agent", help="custom User-Agent header")
    p.add_argument("-H", "--header", action="append", default=[],
                    help="extra request header 'Name: Value', may be given multiple times")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colored output")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the final summary, not per-URL detail")
    p.add_argument("-w", "--threads", type=int, default=20,
                    help="number of URLs to scan concurrently (default: 20; use 1 for old sequential behavior)")
    p.add_argument("--retries", type=int, default=2,
                    help="retries for a URL whose baseline request fails before giving up on it "
                         "(default: 2)")
    p.add_argument("--retry-delay", type=float, default=1.5,
                    help="seconds to wait between retries, doubles each attempt (default: 1.5)")
    p.add_argument("--max-url-time", type=float, default=0,
                    help="give up WAITING on a single URL after this many seconds and move on to "
                         "the next one, marking it skipped, instead of letting one slow target "
                         "tie up a worker thread for the whole run (default: 0, disabled)")
    p.add_argument("--checkpoint", help="path to a checkpoint file used to track completed URLs; "
                                         "combine with --resume to pick a killed/crashed run back up")
    p.add_argument("--resume", action="store_true",
                    help="skip URLs already recorded as done in --checkpoint and merge with --output")
    p.add_argument("--autosave-every", type=int, default=50,
                    help="write a partial JSON report to --output every N completed URLs (default: 50; 0 disables)")
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


def load_checkpoint(path):
    """Return the set of URLs already marked done in a checkpoint file."""
    done = set()
    if not path:
        return done
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    done.add(line)
    except OSError:
        pass
    return done


def append_checkpoint(path, url, lock):
    if not path:
        return
    with lock:
        with open(path, "a") as f:
            f.write(url + "\n")


def rehydrate_result(entry):
    """Turn one entry from a previously-saved JSON report back into a real
    UrlScanResult/ParamResult, matching reporter.save_json's own field
    names exactly, so merging old + new results for --resume works with
    reporter.print_summary/print_url_result/save_json/save_csv unchanged."""
    r = UrlScanResult(entry.get("url"))
    r.skipped_reason = entry.get("skipped_reason")
    for item in entry.get("results", []):
        outcome = {
            "status": item.get("status"),
            "score": item.get("score", 0),
            "marker": item.get("marker"),
            "evidence": item.get("evidence", ""),
            "request": item.get("request", ""),
            "response": "",
        }
        r.add(item.get("parameter"), item.get("check"), outcome)
    return r


def load_previous_results(path):
    """Load a prior --output JSON report, keyed by URL, for --resume merges."""
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    by_url = {}
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        u = item.get("url")
        if u:
            by_url[u] = rehydrate_result(item)
    return by_url


def scan_with_retries(url, session, check_keys, args):
    """Run scanner.scan_url, retrying when the baseline request failed
    (transient network blip) rather than when scan_url raises - scan_url
    itself basically never raises, since http_client.send() already catches
    connection errors/timeouts and turns them into a Result(ok=False, ...),
    which scan_url turns into a normal (non-exceptional) skipped_reason.
    A true, unexpected exception (e.g. something outside requests'
    exception hierarchy) is still caught here as a last resort so one bad
    URL can never kill the whole run."""
    connect_timeout = args.connect_timeout if args.connect_timeout is not None else min(5, args.timeout)
    # requests natively accepts a (connect, read) timeout tuple.
    timeout = (connect_timeout, args.timeout)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    attempt = 0
    delay = args.retry_delay
    while True:
        try:
            result = scanner.scan_url(
                url, session, check_keys, timeout=timeout,
                verify=not args.insecure, proxies=proxies, delay=args.delay,
            )
        except Exception as e:
            attempt += 1
            if attempt > args.retries:
                return skipped_result(url, "scan raised an unexpected error after %d attempt(s): "
                                            "%s: %s" % (attempt, type(e).__name__, e))
            time.sleep(delay)
            delay *= 2
            continue

        if result.skipped_reason and result.skipped_reason.startswith("baseline request failed"):
            attempt += 1
            if attempt > args.retries:
                return result
            time.sleep(delay)
            delay *= 2
            continue

        return result


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
    extra_headers = parse_headers(args.header)

    threads = max(1, args.threads)
    # One session per worker thread avoids sharing a single connection pool's
    # internal state across threads and lets each worker keep its own
    # keep-alive connections to the targets it hits.
    thread_local = threading.local()

    def get_session():
        sess = getattr(thread_local, "session", None)
        if sess is None:
            sess = http_client.build_session(user_agent=args.user_agent, extra_headers=extra_headers)
            thread_local.session = sess
        return sess

    # --- resume support -----------------------------------------------
    already_done = set()
    previous_by_url = {}
    if args.resume:
        already_done = load_checkpoint(args.checkpoint)
        previous_by_url = load_previous_results(args.output)
        skipped_n = sum(1 for u in urls if u in already_done)
        if skipped_n:
            print("Resuming: skipping %d URL(s) already recorded as done." % skipped_n)
    checkpoint_lock = threading.Lock()

    todo = [(i, u) for i, u in enumerate(urls) if u not in already_done]
    total = len(urls)

    print("Loaded %d URL(s) from %s (%d to scan)" % (total, args.file, len(todo)))
    print("Checks enabled: %s" % ", ".join(CHECKS_BY_KEY[k].LABEL for k in check_keys))
    print("Concurrency: %d thread(s), retries: %d" % (threads, args.retries))
    print()

    print_lock = threading.Lock()
    done_count = [0]  # mutable box so the signal handler can read it
    # results[i] holds the result for urls[i] so the report preserves the
    # original file order even though scans complete out of order.
    results = [previous_by_url.get(u) for u in urls]

    def save_partial(reason=""):
        if args.output:
            snapshot = [r if r is not None else skipped_result(u, "not scanned")
                        for u, r in zip(urls, results)]
            reporter.save_json(snapshot, args.output)
            if reason:
                print("\n%s - partial JSON report written to %s" % (reason, args.output))

    def handle_sigint(signum, frame):
        with print_lock:
            print(color("\n\nInterrupted - saving partial progress (%d/%d done)..."
                         % (done_count[0], total), reporter.YELLOW))
        save_partial("Interrupted")
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_sigint)

    def worker(index, url):
        result = scan_with_retries(url, get_session(), check_keys, args)
        return index, url, result

    if threads == 1:
        # Preserves the old sequential behavior/order if requested.
        for n, (i, url) in enumerate(todo, 1):
            if not args.quiet:
                print(color("[%d/%d] scanning %s" % (n, len(todo), url), reporter.BOLD))
            result = scan_with_retries(url, get_session(), check_keys, args)
            results[i] = result
            done_count[0] += 1
            append_checkpoint(args.checkpoint, url, checkpoint_lock)
            if not args.quiet:
                reporter.print_url_result(result, color)
            if args.autosave_every and done_count[0] % args.autosave_every == 0:
                save_partial()
    else:
        # No context manager here on purpose: CPython's ThreadPoolExecutor
        # worker threads are daemon threads, so once we're done *orchestrating*
        # we can shut down with wait=False and return immediately - we don't
        # need to block the whole program on a handful of still-stuck threads
        # past --max-url-time; they die with the process.
        pool = ThreadPoolExecutor(max_workers=threads)
        futures = {pool.submit(worker, i, url): url for i, url in todo}
        start_times = {fut: time.monotonic() for fut in futures}
        pending = set(futures.keys())
        abandoned = set()  # given up WAITING on these; the thread may still be running

        def record(index, url, result):
            results[index] = result
            done_count[0] += 1
            append_checkpoint(args.checkpoint, url, checkpoint_lock)
            if not args.quiet:
                with print_lock:
                    tag = "SKIPPED" if result.skipped_reason else "scanned"
                    print(color("[%d/%d] %s %s" % (done_count[0], len(todo), tag, url), reporter.BOLD))
                    reporter.print_url_result(result, color)
            if args.autosave_every and done_count[0] % args.autosave_every == 0:
                save_partial()

        try:
            # Keep looping only while something we're still actually waiting
            # on remains - an abandoned-but-unfinished future no longer
            # counts, so the run wraps up as soon as everything is either
            # done or given up on, rather than blocking on the slowest target.
            while pending - abandoned:
                done, pending = concurrent.futures.wait(
                    pending, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)

                for fut in done:
                    url = futures[fut]
                    if fut in abandoned:
                        # Already recorded as "too slow" and moved on - its
                        # late result (if any) is simply dropped.
                        continue
                    try:
                        index, url, result = fut.result()
                    except Exception as e:
                        # Should not happen - scan_with_retries already catches
                        # everything - but never let one bad future kill the run.
                        index = urls.index(url)
                        result = skipped_result(url, "worker crashed: %s" % e)
                    record(index, url, result)

                if args.max_url_time:
                    now = time.monotonic()
                    for fut in pending:
                        if fut in abandoned:
                            continue
                        if now - start_times[fut] >= args.max_url_time:
                            url = futures[fut]
                            index = urls.index(url)
                            record(index, url, skipped_result(
                                url,
                                "skipped: exceeded --max-url-time (%.0fs); may still be running "
                                "in the background, result discarded" % args.max_url_time,
                            ))
                            abandoned.add(fut)
        finally:
            pool.shutdown(wait=False)

    all_results = [r if r is not None else skipped_result(u, "not scanned")
                   for u, r in zip(urls, results)]
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
