# tor-exits — Tor exit addresses, refreshed daily

The current Tor exit addresses, taken from the Tor Project's own data and
published as plain lists. Refreshed once a day by a GitHub Actions workflow —
this repository has no server, no credentials and no secrets behind it.

**This is not affiliated with the Tor Project.** It lists where the Tor network
enters the public internet; it is not a statement about Tor. What you block or
allow is your decision — a firewall rule that drops these addresses will affect
everyone using Tor, including people who need it.

## Lists

| file | meaning |
|------|---------|
| `tor-exits.ipv4` | IPv4 exit addresses, one per line, sorted, LF |
| `tor-exits.ipv6` | IPv6 exit addresses, same shape (may legitimately be empty) |
| `tor-exits.csv` | one row per address: `ip,country,as,as_name,first_seen,last_seen` |
| `by-country/<cc>.ipv4` | the same addresses split by country code |
| `crosscheck/bulk.ipv4` | the Tor Project's own bulk list, normalised (sorted) |
| `meta.json` | generation time, counts, source timestamps, counters, attribution |

Reading notes:

- `country` comes from the Tor Project's relay data, `first_seen`/`last_seen`
  are the relay's (UTC, as reported by Onionoo). Country codes are the
  registry view of where a prefix is allocated — not geolocation.
- An address is listed once, owned by the relay with the highest consensus
  weight when several relays share it.
- `meta.json` carries a `generated` timestamp and a `status`; consumers who
  cache should look at it rather than at file mtimes. `raw.githubusercontent`
  caches for a few minutes.
- Exit addresses change constantly (hundreds of relays per day). Compare
  `meta.json.checks.added_since_last_run` / `removed_since_last_run` if you
  need to know how much moved.

## How the lists are built

`refresh.py` (Python standard library only) fetches two public sources and
writes the files above:

- **Onionoo** (`onionoo.torproject.org/details?type=relay&flag=Exit`) — the
  relay records: addresses, country, AS, first/last seen, flags, exit policy.
  The `fields=` parameter keeps the payload small; the full document is ~24 MB.
- **The Tor Project's bulk list** (`check.torproject.org/torbulkexitlist`) —
  plain IPs, no timestamps, no metadata, not even sorted. Kept as a
  cross-check, never as the primary source.

Rules, each one measured against the live sources rather than assumed:

1. `exit_addresses` alone is **not** the exit address set — Onionoo only lists
   addresses there that are not already in `or_addresses`. Using
   `or_addresses ∪ exit_addresses` removes 26 of 27 apparent differences
   against the bulk list.
2. Onionoo keeps relays up to **7 days** after they left the network. Without
   a `running == true` filter ~11 % of the raw union are dead entries.
3. The bulk list is neither a superset nor filtered to port 80 (a port-80
   filter was tested and would yield 492 of 1398). Residual differences in both
   directions are snapshot timing, ~1–4 %.
4. Exit capability is **per address family**. Onionoo's policy summary lists
   either accepted or rejected ports — `reject: ["25"]` means "accept
   everything except 25", only `1-65535` is a reject-all; reading the missing
   `accept` key as "cannot exit" wrongly dropped 374 IPv4 addresses. IPv6
   needs its own `exit_policy_v6_summary`.
5. A broken source never empties a published list: the script refuses to write
   when the result is implausibly small, records `status: error` in `meta.json`
   and exits non-zero so the Action goes red.

## Using the lists

```sh
# all exits
curl -s https://raw.githubusercontent.com/fschaefer/tor-exits/main/tor-exits.ipv4

# only one country, with the full record
curl -s .../tor-exits.csv | awk -F, '$2=="de"'
```

## Attribution and sources

Data by **The Tor Project** — `onionoo.torproject.org` (relay details, updated
hourly) and `check.torproject.org` (bulk exit list). This repository only
reformats and enriches what those two services publish. Not affiliated with,
endorsed by, or supported by the Tor Project.

## Tests

```sh
python3 tests/test_refresh.py     # no network: the sources are faked
```

Covers address collection (union, running filter, per-family policy), numeric
sorting, the shrink guard and the failure path that must leave the lists alone.
