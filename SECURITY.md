# Security Policy

## Reporting a Vulnerability

Security issues are reported as regular [GitHub issues](https://github.com/fschaefer/tor-exits/issues).

Please include:

- a short description of the problem,
- the affected commit (or the `generated` timestamp from `meta.json`),
- a minimal reproducer or the relevant configuration, where possible,
- the expected vs. actual behaviour.

There is no private reporting channel and no bug bounty. Reports are handled
on a best-effort basis, with no fixed response or fix timeline.

## Supported Versions

Only the `main` branch is supported. There is nothing to patch in older
commits: the published lists are regenerated daily, so a fix applies to the
next run.

## Scope

This repository is a data pipeline — there is no daemon, no inbound service
and no credentials. Still, the following count as security issues:

- **Tampering with the published lists**: unauthorised commits, a force-push
  to `main`, or a workflow change that publishes data not derived from the
  sources documented in the README.
- **Source substitution**: a way to make the refresh consume a different
  source, redirect a fetch, or silently change its semantics. The counters in
  `meta.json` (`in_onionoo_not_bulk`, `in_bulk_not_onionoo`,
  `dropped_not_running`, `added_since_last_run`, …) exist to make such changes
  visible — a gap in them is a finding too.
- **Failure of the safety guards**: a state in which a broken or manipulated
  source results in an empty, truncated or wrong list being published, instead
  of the run failing and leaving the previous lists untouched.
- **Workflow or token handling**: misuse of the workflow's `GITHUB_TOKEN`,
  injection through a source response, or anything that lets a third party
  write to this repository through the Action.
- **Supply chain**: unpinned dependencies. The workflow pins the runner image
  and Python version but uses `actions/checkout` and `actions/setup-python` by
  major tag (`@v4`/`@v5`) — that is a deliberate trade-off, and a concrete
  path to abuse it is worth reporting.

Not in scope:

- the *content* of the lists — Tor exit addresses are public data, and whether
  a given address should be blocked is a decision for the consumer, not a bug;
- entries appearing, disappearing or changing between two runs (that is the
  Tor network churning, see `meta.json.checks`);
- the sources' own availability, rate limits or outages — they surface as
  `status: error` in `meta.json` and a failed run.
