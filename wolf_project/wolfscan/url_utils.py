"""
URL / query-string helpers.

Everything in Wolf_Param_Injection works against a single GET parameter at a
time: we take the URL as given, pull out its query string, and for each
parameter in turn we build a new URL with just that one parameter's value
swapped out for a payload - every other parameter keeps its original value.
"""

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote_plus


def parse_query(url):
    """Return the query string of `url` as an ordered list of (name, value)
    tuples. Blank values are kept so a parameter like ?debug= still shows up
    as a target."""
    parsed = urlsplit(url)
    return parse_qsl(parsed.query, keep_blank_values=True)


def has_scheme(url):
    parsed = urlsplit(url)
    return bool(parsed.scheme) and bool(parsed.netloc)


def minimal_encode(value):
    """A deliberately light-touch encoder used for payloads (CRLF, LFI,
    OS command injection) where we need the exact bytes we wrote to reach
    the server - full percent-encoding would mangle payloads that already
    contain literal '%0d%0a' sequences or traversal slashes/dots.

    We only escape the characters that would otherwise break the query
    string itself (space, '&', '#'); everything else - including a '%' we
    deliberately put there ourselves - is left completely alone."""
    return value.replace('&', '%26').replace('#', '%23').replace(' ', '%20')


def build_url(url, qs_list, target_index, payload, raw=False):
    """Build a new URL from `url`'s scheme/host/path, with the query string
    rebuilt from `qs_list` except that the parameter at `target_index` gets
    `payload` as its value.

    raw=False (default): payload is fully percent-encoded, same as a
        browser would encode a form value (used for XSS/SQLi/SSTI/Open
        Redirect payloads).
    raw=True: payload is sent through `minimal_encode` only, so the exact
        characters we wrote (including any literal '%0d%0a', '../', etc.)
        reach the server untouched (used for CRLF/LFI/OS command payloads).
    """
    parsed = urlsplit(url)
    new_qs = list(qs_list)
    name, _old_value = new_qs[target_index]

    if raw:
        parts = []
        for i, (n, v) in enumerate(new_qs):
            if i == target_index:
                parts.append("%s=%s" % (quote_plus(n), minimal_encode(payload)))
            else:
                parts.append("%s=%s" % (quote_plus(n), quote_plus(v)))
        query = "&".join(parts)
    else:
        new_qs[target_index] = (name, payload)
        query = urlencode(new_qs, quote_via=quote_plus)

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
