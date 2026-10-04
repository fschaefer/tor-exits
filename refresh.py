#!/usr/bin/env python3
"""tor-exits — daily Tor exit address lists, enriched, published on GitHub.

Sources (both public, no credentials, no API keys):
  onionoo   https://onionoo.torproject.org/details?type=relay&flag=Exit
            the authoritative records: addresses, country, AS, first/last_seen,
            flags. `fields=` keeps the payload small (full doc is ~24 MB).
  bulk      https://check.torproject.org/torbulkexitlist
            the Tor Project's own plain IP list — no timestamps, no metadata,
            not sorted, not a subset of anything. Used as a cross-check only.

Outputs (all sorted, LF, one record per line unless noted):
  tor-exits.ipv4            exit addresses, IPv4
  tor-exits.ipv6            exit addresses, IPv6 (may legitimately be empty)
  tor-exits.csv             ip,country,as,as_name,first_seen,last_seen
  by-country/<cc>.ipv4      same addresses split by country code
  crosscheck/bulk.ipv4      the Tor Project's bulk list, normalised
  meta.json                 generations, counts, checks, sources, attribution

Rules that were measured, not guessed (2026-10-04):
  1. `exit_addresses` alone is NOT the exit address set. Onionoo only lists
     addresses there that are not already in `or_addresses`; using
     or_addresses ∪ exit_addresses removes 26 of 27 apparent differences
     against the bulk list.
  2. Onionoo keeps relays up to 7 days after they left the network. Without a
     `running == true` filter ~11 % of the raw union are dead entries.
  3. The bulk list is neither a superset nor port-80-filtered (that reading
     was tested and failed: a port-80 filter would give 492 of 1398). The
     residuals in both directions are snapshot timing (~1-4 %); both are
     counted in meta.json so a source changing behaviour is visible.
  4. Exit capability is per address family. Onionoo's summary lists either the
     accepted ports or the rejected ones (`reject: ["25"]` = accept the
     complement) — only `1-65535` in the reject list is a true reject-all.
     Reading the missing `accept` key as "cannot exit" wrongly dropped 374
     IPv4 addresses. IPv6 needs its own `exit_policy_v6_summary`: 908 IPv6 OR
     addresses belong to running exits, but only 529 are on relays with an
     IPv6 policy that accepts something. Non-exits are dropped and counted.

Safety: a broken source must never empty the published list. The script
refuses to write when the result is implausibly small and records the failure
in meta.json (status), exiting non-zero so the Action goes red.
"""
import csv
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

ONIONOO = ("https://onionoo.torproject.org/details?type=relay&flag=Exit&fields="
           "nickname,fingerprint,or_addresses,exit_addresses,country,"
           "country_name,as,as_name,first_seen,last_seen,flags,running,"
           "consensus_weight,exit_policy_summary,exit_policy_v6_summary")
BULK = "https://check.torproject.org/torbulkexitlist"
UA = {"User-Agent": "tor-exits/1.0 (+https://github.com/fschaefer/tor-exits)"}

OUT = os.environ.get("TOR_EXITS_OUT", ".")          # repo root to write into
MIN_RELAYS = int(os.environ.get("TOR_EXITS_MIN_RELAYS", "500"))
MIN_RETAIN = float(os.environ.get("TOR_EXITS_MIN_RETAIN", "0.5"))
TIMEOUT = int(os.environ.get("TOR_EXITS_TIMEOUT", "120"))


def fetch(url, tries=3):
    last = None
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers=UA)
            return urllib.request.urlopen(req, timeout=TIMEOUT).read().decode()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            print(f"fetch {url} attempt {attempt}/{tries} failed: {e}",
                  file=sys.stderr)
            time.sleep(5 * attempt)
    raise RuntimeError(f"fetch failed: {url}: {last}")


def v4_split(text):
    """Hosts of 'host:port' strings, split into IPv4 and IPv6."""
    v4, v6 = set(), set()
    for item in text:
        host = item.rsplit(":", 1)[0] if not item.startswith("[") else item[1:].rsplit("]", 1)[0]
        (v6 if ":" in host else v4).add(host)
    return v4, v6


def policy_accepts(relay, field):
    """Does the relay's exit policy for this family accept anything?

    Onionoo's summary carries either an `accept` list (only those are accepted)
    or a `reject` list (the rest is accepted) — `reject: ["25"]` means "accept
    everything except 25", NOT "accept nothing". Only a reject list containing
    1-65535 is a true reject-all. Reading the missing `accept` key as "cannot
    exit" wrongly dropped 374 IPv4 addresses (measured 2026-10-04).

    True  — accepts at least one port
    False — rejects everything (reject list contains 1-65535)
    None  — no summary for this family at all: not an exit in this family
            (e.g. no IPv6 exit policy) — dropped, but counted separately so
            "reject all" and "no such policy" stay distinguishable
    """
    summary = relay.get(field)
    if not isinstance(summary, dict):
        return None
    if any(str(a) for a in (summary.get("accept") or [])):
        return True
    rejects = [str(r) for r in (summary.get("reject") or [])]
    if "1-65535" in rejects:
        return False
    if rejects:
        return True                      # accepts the complement
    return None


def collect(relays):
    """Build the address sets from the Onionoo records.

    Returns (v4, v6, rows, checks). An address is owned by the relay with the
    highest consensus weight when several relays share it.
    """
    order = sorted(relays, key=lambda r: -(r.get("consensus_weight") or 0))
    v4, v6, owner = set(), set(), {}
    d_not_running = set()
    d_reject_v4, d_nopolicy_v4 = set(), set()
    d_reject_v6, d_nopolicy_v6 = set(), set()
    unknown_v4 = unknown_v6 = 0
    for r in order:
        if "Exit" not in (r.get("flags") or []):
            continue
        addrs = list(r.get("or_addresses") or []) + list(r.get("exit_addresses") or [])
        a4, a6 = v4_split(addrs)
        if not r.get("running"):
            d_not_running |= a4 | a6
            continue
        # each family has its own policy: a relay can be an IPv4 exit and not
        # an IPv6 one, and vice versa
        ok4 = policy_accepts(r, "exit_policy_summary")
        ok6 = policy_accepts(r, "exit_policy_v6_summary")
        unknown_v4 += ok4 is None
        unknown_v6 += ok6 is None
        if ok4 is True:
            for a in sorted(a4):
                v4.add(a)
                owner.setdefault(a, r)
        elif a4:
            (d_reject_v4 if ok4 is False else d_nopolicy_v4).update(a4)
        if ok6 is True:
            for a in sorted(a6):
                v6.add(a)
                owner.setdefault(a, r)
        elif a6:
            (d_reject_v6 if ok6 is False else d_nopolicy_v6).update(a6)
    rows = []
    for a in sorted(v4 | v6, key=lambda s: (ipaddress.ip_address(s).version,
                                            int(ipaddress.ip_address(s)))):
        r = owner[a]
        rows.append({"ip": a, "country": (r.get("country") or "").lower(),
                     "as": r.get("as") or "", "as_name": r.get("as_name") or "",
                     "first_seen": r.get("first_seen") or "",
                     "last_seen": r.get("last_seen") or ""})
    checks = {
        "relays_exit_flag": len(relays),
        "relays_running": sum(1 for r in relays if r.get("running")),
        "relays_reject_all_v4": sum(
            1 for r in relays if r.get("running")
            and policy_accepts(r, "exit_policy_summary") is False),
        "relays_reject_all_v6": sum(
            1 for r in relays if r.get("running")
            and policy_accepts(r, "exit_policy_v6_summary") is False),
        "relays_without_v4_policy_summary": unknown_v4,
        "relays_without_v6_policy_summary": unknown_v6,
        "dropped_not_running": len(d_not_running),
        "dropped_reject_all_v4": len(d_reject_v4 - d_not_running),
        "dropped_no_policy_v4": len(d_nopolicy_v4 - d_not_running),
        "dropped_reject_all_v6": len(d_reject_v6 - d_not_running),
        "dropped_no_policy_v6": len(d_nopolicy_v6 - d_not_running),
        "addresses_without_country": sum(1 for r in rows if not r["country"]),
    }
    return v4, v6, rows, checks


def sort_ips(ips):
    return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version,
                                      int(ipaddress.ip_address(s))))


def read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def write_lines(path, items):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write("".join(f"{i}\n" for i in items))


def guard(old, new, label):
    """Refuse to publish an implausible shrink (broken source, not real churn)."""
    if len(new) < MIN_RELAYS:
        raise RuntimeError(f"{label}: only {len(new)} addresses, "
                           f"below the floor {MIN_RELAYS} — source broken?")
    if old and len(new) < MIN_RETAIN * len(old):
        raise RuntimeError(f"{label}: {len(new)} addresses vs {len(old)} before "
                           f"(< {MIN_RETAIN:.0%}) — refusing to shrink the list")


def write_meta(path, meta):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
        f.write("\n")


def main():
    out = OUT
    started = time.time()
    prev4 = read_lines(os.path.join(out, "tor-exits.ipv4"))
    meta_path = os.path.join(out, "meta.json")
    meta = {
        "generated": int(started),
        "status": "ok",
        "sources": {
            "onionoo": {"url": ONIONOO.split("&fields=")[0]},
            "bulk": {"url": BULK},
        },
        "attribution": {
            "data": "The Tor Project (onionoo.torproject.org, "
                    "check.torproject.org) — public relay data",
            "note": "Not affiliated with the Tor Project. Listing exits is "
                    "not a statement about Tor; block or allow at your own "
                    "discretion.",
        },
    }
    try:
        onion = json.loads(fetch(ONIONOO))
        relays = onion.get("relays") or []
        if len(relays) < MIN_RELAYS:
            raise RuntimeError(f"onionoo returned only {len(relays)} relays")
        meta["sources"]["onionoo"]["relays_published"] = onion.get("relays_published")
        v4, v6, rows, checks = collect(relays)
        guard(prev4, v4, "tor-exits.ipv4")

        bulk = set(l.strip() for l in fetch(BULK).split("\n") if l.strip())
        checks["bulk_list_ips"] = len(bulk)
        checks["in_onionoo_not_bulk"] = len(v4 - bulk)
        checks["in_bulk_not_onionoo"] = len(bulk - v4)
        mt, mo = set(sort_ips(v4)), set(sort_ips(prev4))
        checks["added_since_last_run"] = len(mt - mo)
        checks["removed_since_last_run"] = len(mo - mt)

        write_lines(os.path.join(out, "tor-exits.ipv4"), sort_ips(v4))
        write_lines(os.path.join(out, "tor-exits.ipv6"), sort_ips(v6))
        write_lines(os.path.join(out, "crosscheck/bulk.ipv4"), sort_ips(bulk))
        with open(os.path.join(out, "tor-exits.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "country", "as", "as_name",
                                              "first_seen", "last_seen"],
                               lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
        by_cc = {}
        for r in rows:
            if r["country"]:
                by_cc.setdefault(r["country"], []).append(r["ip"])
        for cc, ips in by_cc.items():
            write_lines(os.path.join(out, f"by-country/{cc}.ipv4"), sort_ips(ips))
        meta["counts"] = {
            "ipv4": len(v4), "ipv6": len(v6), "csv_rows": len(rows),
            # complete, alphabetical: stable diffs. The shortlist below is the
            # same data sorted by size (a dict would lose that under sort_keys).
            "by_country": {cc: len(ips) for cc, ips in sorted(by_cc.items())},
            "top_countries": [[cc, len(ips)] for cc, ips in
                              sorted(by_cc.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:10]],
            "countries": len(by_cc),
        }
        meta["checks"] = checks
        meta["duration_s"] = round(time.time() - started, 1)
        write_meta(meta_path, meta)
        print(f"ok: {len(v4)} IPv4 / {len(v6)} IPv6 addresses, "
              f"{len(by_cc)} countries, "
              f"+{checks['added_since_last_run']}/-{checks['removed_since_last_run']} "
              f"since the last run, onionoo-only {checks['in_onionoo_not_bulk']}, "
              f"bulk-only {checks['in_bulk_not_onionoo']}")
        return 0
    except Exception as e:                      # noqa: BLE001 - report, never wipe
        meta["status"] = "error"
        meta["error"] = f"{type(e).__name__}: {e}"
        write_meta(meta_path, meta)
        print(f"ERROR: {meta['error']}", file=sys.stderr)
        print("list files left untouched", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
