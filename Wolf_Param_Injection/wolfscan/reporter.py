import csv
import json

from .checks import CHECKS_BY_KEY, FOUND, CHECK, NOT_FOUND

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
GREY = "\033[90m"
CYAN = "\033[96m"


class Colorizer:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def __call__(self, text, color):
        if not self.enabled:
            return text
        return color + text + RESET


def status_color(status):
    return {FOUND: RED, CHECK: YELLOW, NOT_FOUND: GREY}.get(status, RESET)


def print_url_result(url_result, color: Colorizer, show_evidence=True, max_snippet=200):
    print()
    print(color("=" * 78, GREY))
    print(color("URL: ", BOLD) + url_result.url)

    if url_result.skipped_reason:
        print(color("  SKIPPED - %s" % url_result.skipped_reason, YELLOW))
        return

    by_param = {}
    for r in url_result.results:
        by_param.setdefault(r.param_name, []).append(r)

    for param_name, checks in by_param.items():
        print(color("  Parameter: %s" % param_name, BOLD + CYAN if color.enabled else ""))
        for r in checks:
            label = CHECKS_BY_KEY[r.check_key].LABEL
            line = "    [%-45s] %s" % (label, r.status)
            print(color(line, status_color(r.status)))
            if show_evidence and r.status in (FOUND, CHECK) and r.evidence:
                print("        -> %s" % r.evidence)
                if r.request:
                    print("        request : %s" % r.request)


def print_summary(all_results, color: Colorizer):
    counts = {}
    for key in CHECKS_BY_KEY:
        counts[key] = {FOUND: 0, CHECK: 0, NOT_FOUND: 0}

    scanned = 0
    skipped = 0
    for ur in all_results:
        if ur.skipped_reason:
            skipped += 1
            continue
        scanned += 1
        for r in ur.results:
            counts[r.check_key][r.status] = counts[r.check_key].get(r.status, 0) + 1

    print()
    print(color("=" * 78, GREY))
    print(color("SUMMARY", BOLD))
    print("  URLs scanned: %d   URLs skipped: %d" % (scanned, skipped))
    print()
    print("  %-45s %8s %8s %10s" % ("Check", "Found", "Check", "Not Found"))
    for key, module in CHECKS_BY_KEY.items():
        c = counts[key]
        print("  %-45s %8s %8s %10s" % (
            module.LABEL,
            color(str(c.get(FOUND, 0)), RED),
            color(str(c.get(CHECK, 0)), YELLOW),
            str(c.get(NOT_FOUND, 0)),
        ))
    print(color("=" * 78, GREY))


def save_json(all_results, path):
    data = []
    for ur in all_results:
        entry = {"url": ur.url, "skipped_reason": ur.skipped_reason, "results": []}
        for r in ur.results:
            entry["results"].append({
                "parameter": r.param_name,
                "check": r.check_key,
                "label": CHECKS_BY_KEY[r.check_key].LABEL,
                "status": r.status,
                "score": r.score,
                "marker": r.marker,
                "evidence": r.evidence,
                "request": r.request,
            })
        data.append(entry)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def save_csv(all_results, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "parameter", "check", "label", "status", "score", "marker", "evidence", "request"])
        for ur in all_results:
            if ur.skipped_reason:
                writer.writerow([ur.url, "", "", "", "SKIPPED: %s" % ur.skipped_reason, "", "", "", ""])
                continue
            for r in ur.results:
                writer.writerow([
                    ur.url, r.param_name, r.check_key, CHECKS_BY_KEY[r.check_key].LABEL,
                    r.status, r.score, r.marker or "", r.evidence, r.request,
                ])
