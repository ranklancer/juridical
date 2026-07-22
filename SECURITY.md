# Security Policy

Juridical is an authorization and audit control plane; the security of
Juridical itself is a first-class concern.

## Supported versions

Juridical is pre-1.0 and ships from `main`. Security fixes are applied to
`main` and the latest tagged release.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** - do not open a public
issue, pull request, or discussion.

Use GitHub's **private vulnerability reporting** for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include: affected component/version/commit, impact, reproduction steps or a
   proof of concept, and any known mitigations.

This channel is private to the maintainers and keeps the report out of public
view until a fix is available.

## Response targets (SLAs)

Good-faith targets, not contractual guarantees:

| Stage | Target |
|---|---|
| Acknowledge receipt | within 3 business days |
| Triage / initial assessment | within 7 business days |
| Fix or mitigation plan (confirmed issue) | within 30 days, severity-dependent |
| Coordinated public disclosure | by mutual agreement after a fix ships |

Critical, actively-exploited issues are prioritized over these windows.

## Safe harbor

We support good-faith security research and will not pursue or support legal
action against researchers who:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service interruption;
- only interact with systems and data they own or are authorized to test;
- report promptly and give us reasonable time to remediate before disclosure;
- do not access or exfiltrate more data than necessary to demonstrate the
  issue.

Activity that violates other laws or harms users or third parties is outside
this safe harbor. We are happy to credit reporters who wish to be acknowledged.

## Scope

In scope: the Juridical source in this repository and the release artifacts
published from it. Out of scope: third-party dependencies (report upstream)
and issues requiring privileged local access Juridical does not itself grant.

## Recovering the audit log after an unclean shutdown

juridical will refuse to start if its audit log fails integrity checks. This is deliberate: the engine will not append to a chain it cannot vouch for. Diagnose before changing anything.

**Step 1 — diagnose (safe, changes nothing):**
`juridical audit verify --audit-log <path>`

**Step 2 — interpret the exit code:**

- **0** — the log is intact. If the engine still will not start, the cause is elsewhere.
- **2 — Truncation or tamper detected. STOP. This is a security incident, not a maintenance task.** Records are missing or altered. Do not adopt a new anchor: doing so would permanently bless the altered log as trusted. Preserve the log and anchor exactly as they are, and escalate.
- **3 — The log is ahead of its anchor.** Consistent with power loss between a record being written and its anchor being updated. It is *also* consistent with someone appending a forged record — the two are indistinguishable from the files alone. Judge using independent evidence: was there an actual unclean shutdown at that time? Does the trailing record correspond to an action you expected? If you cannot account for the trailing record, treat it as case 2 and escalate.
- **4 — No anchor exists for this log.** Expected when upgrading a deployment that predates anchoring. Proceed to Step 3.
- **5 — The anchor is corrupt or unreadable** (as distinct from absent). Do not delete it reflexively — inspect it first; a corrupt anchor may itself be evidence.

**Step 3 — adopt an anchor (only for exit code 4, or exit code 3 after you have satisfied yourself the trailing record is genuine):**

If an anchor exists and you have concluded it must be replaced, remove it explicitly first. That removal is intentionally a separate manual act — there is no `--force` flag, because an automatic overwrite is precisely how a truncated log would be laundered into a trusted one.

`juridical audit adopt-anchor --audit-log <path>`

This verifies the chain and refuses if it does not check out.

**Step 4 — confirm:** re-run `juridical audit verify --audit-log <path>` and expect exit code 0. The engine will now start.

**What this protects, and what it does not.** The anchor sits on the same filesystem as the log. It raises the cost of undetected tampering from altering one file to altering two consistently — and nothing more. An adversary with equal write access, including root or the account the service runs as, defeats it. It is not notarization and not a WORM store. Detecting that class of adversary requires shipping records off-host or signing them under a key the service does not hold.
