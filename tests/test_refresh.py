"""Tests for refresh.py — no network: the sources are faked.

Covers the rules that were measured against the live sources:
or_addresses ∪ exit_addresses, the running filter, per-family exit policy
(IPv4 vs. IPv6, reject-all vs. reject-a-few), numeric sorting, the shrink
guard, and the failure path that must never empty the published lists.
Run: python3 tests/test_refresh.py
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import refresh

FAILS = 0


def check(name, cond, got=""):
    global FAILS
    print(("OK   " if cond else "FAIL ") + name, "" if cond else got)
    if not cond:
        FAILS += 1


def pol(kind, ports=None):
    """Onionoo policy summary: 'accept' ports, 'reject' ports, or absent."""
    if kind is None:
        return None
    if kind == "accept":
        return {"accept": list(ports or ("80",))}
    return {"reject": list(ports or ("1-65535",))}


def relay(nick, or_addr, exit_addr, cc, running=True, weight=1,
          v4=("accept", ("80",)), v6=None, flags=("Exit", "Running")):
    r = {"nickname": nick, "fingerprint": nick, "or_addresses": or_addr,
         "exit_addresses": exit_addr, "country": cc, "as": "AS1",
         "as_name": "Test AS", "first_seen": "2026-01-01 00:00:00",
         "last_seen": "2026-10-04 13:00:00", "flags": list(flags),
         "running": running, "consensus_weight": weight}
    s4, s6 = pol(*v4) if v4 else None, (pol(*v6) if v6 else None)
    if s4 is not None:
        r["exit_policy_summary"] = s4
    if s6 is not None:
        r["exit_policy_v6_summary"] = s6
    return r


RELAYS = [
    # address only in or_addresses (the case behind 26 of 27 differences)
    relay("a", ["10.0.0.10:9001"], ["10.0.0.10"], "de", weight=100),
    # separate exit address
    relay("b", ["10.0.0.2:9001"], ["10.0.0.20"], "nl", weight=90),
    # IPv6: needs its own IPv6 policy to count as an IPv6 exit
    relay("c", ["[2001:db8::1]:9001"], ["[2001:db8::1]"], "se", weight=80,
          v6=("accept", ("443",))),
    # left the network -> dropped, counted
    relay("d", ["10.0.0.30:9001"], ["10.0.0.30"], "us", running=False, weight=70),
    # IPv4 reject-all -> dropped, counted as reject_all
    relay("e", ["10.0.0.40:9001"], ["10.0.0.40"], "fr", weight=60,
          v4=("reject", ("1-65535",))),
    # no IPv4 policy summary at all -> dropped, counted separately
    relay("f", ["10.0.0.50:9001"], ["10.0.0.50"], "at", weight=50, v4=None),
    # IPv6 address but no IPv6 policy -> dropped
    relay("h", ["[2001:db8::2]:9001"], ["[2001:db8::2]"], "dk", weight=40),
    # IPv6 reject-all -> dropped
    relay("i", ["[2001:db8::3]:9001"], ["[2001:db8::3]"], "no", weight=30,
          v6=("reject", ("1-65535",))),
    # IPv4 reject-a-few -> accepts the complement, MUST be kept (the trap)
    relay("j", ["10.0.0.60:9001"], ["10.0.0.60"], "pl", weight=20,
          v4=("reject", ("25",))),
    # same for IPv6
    relay("k", ["[2001:db8::4]:9001"], ["[2001:db8::4]"], "cz", weight=15,
          v6=("reject", ("25",))),
    # shared address, lower weight -> owner stays the higher-weight relay
    relay("g", ["10.0.0.10:9002"], ["10.0.0.10"], "us", weight=10),
]


def main():
    v4, v6, rows, checks = refresh.collect(RELAYS)

    check("or ∪ exit: address only in or_addresses is included",
          "10.0.0.10" in v4, sorted(v4))
    check("separate exit_addresses is included", "10.0.0.20" in v4)
    check("reject-a-few means accept the rest -> IPv4 kept", "10.0.0.60" in v4)
    check("reject-a-few means accept the rest -> IPv6 kept",
          "2001:db8::4" in v6, sorted(v6))
    check("IPv6 with its own IPv6 policy is included, IPv4 set untouched",
          "2001:db8::1" in v6 and not (v6 & v4), (sorted(v6), sorted(v4)))
    check("relay that left the network is dropped", "10.0.0.30" not in v4)
    check("IPv4 reject-all is dropped", "10.0.0.40" not in v4)
    check("IPv4 without any policy summary is dropped", "10.0.0.50" not in v4)
    check("IPv6 without IPv6 policy is dropped", "2001:db8::2" not in v6)
    check("IPv6 reject-all is dropped", "2001:db8::3" not in v6)
    check("dropped counters: running, reject-all and no-policy are separate",
          checks["dropped_not_running"] == 1
          and checks["dropped_reject_all_v4"] == 1
          and checks["dropped_no_policy_v4"] == 1
          and checks["dropped_reject_all_v6"] == 1
          and checks["dropped_no_policy_v6"] == 1, checks)
    check("shared address keeps the highest-weight owner (de, not us)",
          next(r for r in rows if r["ip"] == "10.0.0.10")["country"] == "de")
    check("rows are sorted numerically, IPv4 before IPv6",
          [r["ip"] for r in rows] == ["10.0.0.2", "10.0.0.10", "10.0.0.20",
                                      "10.0.0.60", "2001:db8::1", "2001:db8::4"],
          [r["ip"] for r in rows])

    check("policy_accepts: accept -> True, reject-a-few -> True, "
          "reject-all -> False, absent -> None",
          refresh.policy_accepts(relay("x", [], [], "de"), "exit_policy_summary") is True
          and refresh.policy_accepts(relay("w", [], [], "de", v4=("reject", ("25",))),
                                     "exit_policy_summary") is True
          and refresh.policy_accepts(relay("y", [], [], "de",
                                           v4=("reject", ("1-65535",))),
                                     "exit_policy_summary") is False
          and refresh.policy_accepts(relay("z", [], [], "de", v4=None),
                                     "exit_policy_summary") is None)

    check("sort_ips is numeric, not lexicographic",
          refresh.sort_ips(["10.0.0.9", "10.0.0.10", "10.0.0.2"])
          == ["10.0.0.2", "10.0.0.9", "10.0.0.10"])

    a4, a6 = refresh.v4_split(["1.2.3.4:9001", "[2001:db8::1]:443"])
    check("v4_split handles host:port and [v6]:port",
          a4 == {"1.2.3.4"} and a6 == {"2001:db8::1"}, (a4, a6))

    refresh.MIN_RELAYS = 3
    refresh.MIN_RETAIN = 0.5
    try:
        refresh.guard([], {"1.1.1.1"}, "test")
        check("guard refuses too few addresses", False)
    except RuntimeError:
        check("guard refuses too few addresses", True)
    try:
        refresh.guard(["1.1.1.%d" % i for i in range(1, 11)],
                      {"1.1.1.1", "1.1.1.2", "1.1.1.3"}, "test")
        check("guard refuses an implausible shrink", False)
    except RuntimeError:
        check("guard refuses an implausible shrink", True)

    # --- end to end against a temp repo, sources faked
    tmp = tempfile.mkdtemp(prefix="tor-exits-")
    onion = {"relays_published": "2026-10-04 13:00:00", "relays": RELAYS}
    bulk = "10.0.0.10\n10.0.0.20\n10.0.0.99\n"
    cache = {"onionoo": json.dumps(onion), "bulk": bulk}
    real_fetch = refresh.fetch
    refresh.fetch = lambda url, tries=3: (cache["onionoo"] if "onionoo" in url
                                          else cache["bulk"])
    refresh.OUT = tmp
    refresh.MIN_RELAYS = 1
    try:
        rc = refresh.main()
        check("run 1 exits 0", rc == 0, rc)
        check("ipv4 list written",
              os.path.isfile(os.path.join(tmp, "tor-exits.ipv4")))
        check("by-country written for each country with data",
              sorted(os.listdir(os.path.join(tmp, "by-country")))
              == ["cz.ipv4", "de.ipv4", "nl.ipv4", "pl.ipv4", "se.ipv4"],
              os.listdir(os.path.join(tmp, "by-country")))
        check("csv uses LF, not CRLF",
              b"\r\n" not in open(os.path.join(tmp, "tor-exits.csv"), "rb").read())
        m = json.load(open(os.path.join(tmp, "meta.json")))
        check("meta status ok", m["status"] == "ok", m.get("status"))
        check("meta counts match the files",
              m["counts"]["ipv4"] == 4 and m["counts"]["ipv6"] == 2, m["counts"])
        check("top_countries is size-sorted (survives sort_keys)",
              m["counts"]["top_countries"][0] == ["nl", 2]
              and len(m["counts"]["top_countries"]) == 5,
              m["counts"]["top_countries"])
        check("cross-check counters are computed",
              m["checks"]["in_onionoo_not_bulk"] == 2      # 10.0.0.2, 10.0.0.60
              and m["checks"]["in_bulk_not_onionoo"] == 1,  # 10.0.0.99
              m["checks"])
        check("first run: everything is new",
              m["checks"]["added_since_last_run"] == 4
              and m["checks"]["removed_since_last_run"] == 0, m["checks"])
        check("csv has one row per published address",
              len([l for l in open(os.path.join(tmp, "tor-exits.csv"))
                   if l.strip()]) - 1 == 6)

        # broken source: nothing may be lost
        before = open(os.path.join(tmp, "tor-exits.ipv4")).read()
        def boom(url, tries=3):
            raise RuntimeError("source down")
        refresh.fetch = boom
        rc = refresh.main()
        check("broken source exits non-zero", rc == 1, rc)
        check("published list untouched on failure",
              open(os.path.join(tmp, "tor-exits.ipv4")).read() == before)
        m = json.load(open(os.path.join(tmp, "meta.json")))
        check("failure is recorded in meta.json",
              m["status"] == "error" and "source down" in m["error"], m.get("error"))

        # unchanged data -> 0/0 churn
        refresh.fetch = lambda url, tries=3: (cache["onionoo"] if "onionoo" in url
                                              else cache["bulk"])
        rc = refresh.main()
        m = json.load(open(os.path.join(tmp, "meta.json")))
        check("unchanged run reports 0/0 churn",
              m["checks"]["added_since_last_run"] == 0
              and m["checks"]["removed_since_last_run"] == 0, m["checks"])
    finally:
        refresh.fetch = real_fetch
        shutil.rmtree(tmp)

    print("FAILS:", FAILS)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
