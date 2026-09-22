# Security notes

## This repository ships no credentials

There is no SSH key, no password, no agent key and no certificate in this repository or in its
history. Every credential the lab uses is generated locally by `New-LabSecrets.ps1` into
`.lab-secrets/`, which is excluded by `.gitignore` and has never been
committed.

Raw evidence is excluded for the same reason. Live runs record account names, source addresses
and scheduled task contents, so only two sanitised summaries are committed:
`evidence/README.md` and `evidence/validation-status.md`.

If you clone this, you start with no credentials. That is intended. See
[docs/fresh-clone.md](docs/fresh-clone.md).

## What the lab deliberately does

This is a detection lab, so some of it looks like the thing it detects. Worth being explicit:

- `agents/linux/invoke-scenario.sh` and `agents/windows/Invoke-Scenario.ps1` create a local account, make failed
  logon attempts against it, and write a cron entry or scheduled task. They do this to generate
  the events the rules are written for. Both refuse to run on any host other than the lab
  endpoint they belong to, clean up everything they created through a trap, and write a record of
  what they did.
- `tests/s1-burst.sh` starts a throwaway `sshd` on a high port to produce authentication failures
  against a disposable account.

None of these are useful as attack tools and none of them touch anything outside the VM they run
on. They are here because a detection you have never seen fire is not a detection.

## Network exposure

The lab runs on a private network with outbound NAT and no route in: an internal switch on
Hyper-V, a host-only adapter alongside a NAT network on VirtualBox. The manager's firewall is
set by `manager/install-manager.sh` to accept SSH and 443 only from the host, and agent traffic
on 1514 only from the endpoint addresses in `lab.config.json`. The Windows endpoint's OpenSSH
listener is scoped to the host address by a rule its unattend file writes. The Wazuh web
interface is not reachable from anywhere except the host.

The manager runs three root-owned helpers the dashboard is granted through sudoers by exact
path, rather than a general grant: an authenticated indexer search over the admin certificate,
the per-endpoint baseline, and the dashboard credentials. The indexer admin
password is never read, never copied and never placed on a command line; the credentials helper
prints it to standard output rather than taking it as an argument. Every sudoers file is
validated with `visudo -c -f` before it is installed.

The lab dashboard binds `127.0.0.1` only, never `0.0.0.0`, and requires a per-run token on every
API call.

## Before making this repository public

Run through this list. Some of it cannot be checked mechanically.

- [ ] `git log --all --name-only | sort -u` and confirm nothing under `.lab-secrets/` or
      `evidence/` other than the two whitelisted files has ever appeared.
- [ ] Read `docs/Wazuh-Threat-Detection-Proposal.pdf`. It was written for a named reviewer and
      may identify them or their company. Its text is font-subset encoded, so it cannot be
      scanned automatically and needs a human to open it.
- [ ] Confirm the addresses in this repository are still the RFC 1918 lab range `172.29.70.0/24`
      and that no real network has been substituted.
- [ ] Rotate `.lab-secrets/` if the keypair has ever been copied to a machine you do not control.

## Reporting something

This is a personal lab project rather than deployed software. If you find a problem in it, open
an issue.
