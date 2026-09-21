# Lab dashboard

The front door for the lab. It starts and stops it, shows what it is costing, and answers the
question the project exists to answer: are all six detections alive, and when did each one last
fire.

Open it with `Lab.cmd` at the root of the repository. This is not how the lab gets built; follow
`deployment-guide.md` for that, once.

## Before it opens

The page starts as a small box that checks the machine, and hands over to the dashboard only once
nothing is blocking. Ten reads, none of which change anything:

| Check | Why it is here |
| --- | --- |
| Administrator rights | Hyper-V does not answer an ordinary session. |
| Hardware virtualization | SVM on AMD, VT-x on Intel. Off in firmware, and no VM starts at all. |
| Hyper-V platform | The management service, which is the honest test that the platform is live. |
| Lab network | The `Wazuh-Lab` switch, and a NAT covering 172.29.70.0/24. |
| Lab virtual machines | All three present, under the names this tool expects. |
| Lab credentials | `.lab-secrets`. A fresh clone has none, and this is where that surfaces. |
| OpenSSH client | Everything read from inside the guests travels over SSH. |
| Memory headroom | 16 GB for all three. Advisory. |
| Disk headroom | On whichever drive the VMs are actually on. Advisory. |
| Autostart locked off | 16 GB should never wake on its own. Advisory. |

The first seven block. The last three warn instead: they say the lab will struggle rather than
that it cannot start, so they cost one click rather than a fix.

Everything passing opens the dashboard on its own, in about a second. Anything failing leaves the
box where it is and names the cause and the command that fixes it, with "Check again" beside it.

There is always an "Open anyway". A check that is wrong should not lock you out of your own tool,
and every panel below already says what it cannot read.

Virtualization is worth one note, because the obvious way to test it is wrong. Once Hyper-V is
running it owns the virtualization extensions, and `Win32_Processor` then reports
`VirtualizationFirmwareEnabled` as false, because Windows can no longer see the firmware setting
it is already using. Reading that field on its own therefore reports "disabled" on a machine
whose VMs are running. `HypervisorPresent` is tested first for that reason.

## Lab access

The logins, in a panel under the host strip:

| Where | Who |
| --- | --- |
| Wazuh web interface | `https://172.29.70.10`, user `admin` |
| Manager | `labadmin@172.29.70.10`, key or console password |
| Linux endpoint | `labadmin@172.29.70.30`, key or console password |
| Windows endpoint | `labadmin`, at the Hyper-V console |

Addresses and usernames are always shown. Passwords arrive masked and stay masked until you press
"Show passwords", and every value has a Copy button.

The console password is read from `.lab-secrets` at the moment of the request. The Wazuh password
is different: the installer generates it and writes it into a root-owned log, so that one needs
the one-time setup below. Until then the row says so rather than showing an empty field.

Both are fetched once when the page opens rather than on the poll. A password does not change
every three seconds and there is no sense paying an SSH round trip for one that has not.

## Bringing the lab up

One button. It runs in order, because the agents need a manager to connect to:

1. Start the manager.
2. Wait for it to finish booting and answer on SSH.
3. Wait for `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` and `filebeat` to be active.
4. Start both endpoints.
5. Wait for both agents to check in.

"Take the lab down" reverses it. The endpoints stop first and the manager last, so it is not left
talking to nothing, and the indexer is the final thing to close. Nothing is ever forced.

Each phase has its own deadline. If one expires the sequence stops and says which phase it was in
and what it was waiting for, rather than hanging. Measured on this lab, a cold start from all
three off reaches ready in about 35 seconds, most of which is the Wazuh services starting.

While a sequence is running the per-VM buttons are disabled, so a click cannot fight it.

## What it shows

**Lab health.** Every Wazuh service on the manager, and whether each agent is checking in.

**Detection coverage.** The six detection rules and the two seed rules they count, read from
`lab_rules.xml` on disk, crossed with what has actually fired on the manager. This is the panel
worth showing someone: it is the project's results table, except current rather than historical.

A rule that exists and has never fired is the state worth noticing, and it is invisible in any
view built from alerts alone, because nothing is there to see. Here it reads "never".

**Alert sequence score.** The one panel showing a model rather than a rule. Every rule above
judges a single event; this judges a run of them. Alerts are bucketed into five minute windows,
each window is scored, and the last twelve are drawn as a strip with the rules that fired in the
worst one underneath.

The number it leads with is not the model's. The model answers how unusual a window is, which is
not how bad it is: forty level 3 alerts and one level 12 beside a new account can look alike to
it. Severity is a 0 to 100 composite of six terms with the model as one of them, and the lab's
own case, credential access followed by persistence, earns a multiplier because that pairing is a
chain rather than two events. On the worked example in
[the report](../../../docs/Detection-Modelling-Report.pdf), a quiet window of session opens
scores 16, a brute force burst that trips rule 100111 scores 54, and the same burst with an
account creation beside it scores 78. The rules in step 4 cannot tell those last two apart: they
report a brute force alert and an account creation alert, and nothing saying they belong
together. Those three numbers come out of `score.py` when the report is built, so this paragraph
and the PDF cannot disagree.

The weights are judgement rather than fitted parameters, and they live in one place,
`05-detection-modelling/scorer/score.py`, so disagreeing with them is an edit rather than an
argument. The info mark beside the title opens the method and the formula: hover to read it,
click to pin it, click anywhere else to close it. It sits in the panel header rather than in the
polled region so that a redraw every three seconds cannot close it while somebody is reading.

A completed window reaching elevated, 50 or above, becomes a **finding**. Each one can be
expanded to show every term, its raw reading, its normalised value, its weight and what it
contributed, and then the rules that fired inside it with their ATT&CK ids. **Export findings**
writes that to a PDF under `evidence/findings/`, built from the poll that was on screen at the
time rather than from a fresh read, so the document and the screen it came from agree. It lands
under `evidence/` because a finding carries account names and source addresses off a live
endpoint, and everything there is gitignored.

That path is the longest thing here between a change and its consequence: a Python block inside
a PowerShell here-string, two files substituted into it, base64 encoded, over SSH, onto the
manager, back as JSON, into a browser. A mistake anywhere in it looks the same from here, which
is a panel that is quietly wrong. `../../tests/test_dashboard_scoring.py` assembles and runs it
exactly as this script does, against alerts written so the answers are known in advance. No VM,
no SSH, about a second. Run it before touching the remote script, `score.py` or `model.json`.

The newest bar is drawn hollow because that window is still filling. Its alert count is low for a
reason that has nothing to do with what is happening, so its score is not comparable with the
completed ones and the panel says so rather than drawing a dip that looks like an attack stopping.

Bars are severity on a fixed 0 to 100 scale, never scaled to the tallest bar on screen.
Auto-scaling was tried and rejected: a severity is meant to mean the same thing on a quiet
afternoon as during an incident, and stretching whatever is on screen to fill the panel makes a
quiet hour look exactly like a bad one.

What the panel is careful not to claim is the important part. The model was fitted on eight public
networks, because no public dataset contains this lab's rules, and it has never been measured
here. Its own measurement travels in the model file and is printed on the panel: average precision
0.177 against a 0.021 base rate, on networks it had never seen. That is eight times better than
chance and well short of an alerting rule, so the panel is triage ordering and says as much.

The model file is read from `05-detection-modelling/scorer/` at startup and travels inside the
same payload as everything else, so nothing is installed on the manager. A clone that has never
run the modelling step gets the rest of the dashboard and a panel saying the model is absent.

**Pipeline.** Manager disk, alert volume over the last twelve hours, the busiest hour, and, once
the one-time setup has run, indexer health, alert document count, index size and whether the
retention policy is still attached. Retention is not something Wazuh ships, so an index with no
policy is a real finding rather than a cosmetic one.

**Recent alerts.** Time, agent, rule, level, description and ATT&CK technique. A dropdown narrows
the list to 5, 10, 15, 25 or 50 and remembers the choice. The manager always sends 50, so changing
that figure redraws instantly rather than going back over SSH.

**Virtual machines.** Live CPU, memory and uptime per VM, its autostart setting, which ports are
answering, and start, shut down, restart and force off.

Above all of it is a host strip: CPU, memory, how much the lab is using, and free space per drive.

## Advanced

The toggle in the top right corner. Off by default, and remembered between visits.

It adds start, stop and restart per Wazuh service, a restart for the Linux agent, the manager log,
the scenario runners below, and a Lab actions panel with the autostart lock, shut down all, and
stop dashboard.

The point of the split is that the normal view should be readable at a glance, and that nothing in
it can stop a service by accident.

## Running a scenario

Under Advanced, each of the three scenarios can be run on either endpoint, as the attack case or
the benign comparison. Press one and the detection appears in the coverage panel a few seconds
later, which is the whole project in a single gesture.

These deliberately do what the rules detect: create a local account, make failed logon attempts
against it, write a cron entry or a scheduled task. Each driver refuses to run anywhere except its
own endpoint, removes everything it created through a trap, and writes a record of the run. Each
button asks for confirmation first.

The benign comparison is the case that matters most. One failed logon instead of six should stay
below the threshold, and that it does is what makes the attack run mean anything.

Linux goes over SSH to a wrapper whose six exact invocations are named in sudoers. Windows goes
over PowerShell Direct, which needs no network and no open port on that machine.

## One-time setup

The dashboard works the moment SSH does. Service state, VM state, disk and the rule inventory all
read without any special rights, and anything it cannot read it names rather than showing an empty
panel, which is the failure that would otherwise look like a healthy lab producing nothing.

What needs granting once, with the lab running:

```
.\Enable-LabDashboard.ps1
```

It asks for the lab account's sudo password, uses it for that run, and stores nothing. It grants:

- Membership of the `wazuh` group for `labadmin`, which makes the alert log and `ossec.log`
  readable. Reading alerts is the main thing this does and it should not need root.
- A sudoers rule permitting exactly `systemctl start`, `stop` and `restart` on the named Wazuh
  units, `agent_control -l`, and the indexer summary. Nothing else.
- `/usr/local/bin/lab-dashboard-indexer` on the manager, which reports cluster health, alert
  volume and retention. It authenticates with the indexer's admin certificate, so the admin
  password is not involved in any of it.
- `/usr/local/bin/lab-dashboard-creds`, which returns the Wazuh web interface login for the Lab
  access panel. This is the one thing here that hands over a password. It is read from the
  installer's own log and printed on stdout rather than passed as an argument, so it never
  appears in a process list, and it comes back over the SSH connection already open. Leave this
  file off the manager if you would rather the dashboard never saw it: the panel then says it
  could not read it, and nothing else changes.
- On the Linux endpoint, the scenario driver at a stable path plus the six exact sudoers entries.

Every sudoers file is checked with `visudo` before installation, and nothing is written if that
fails, because a broken sudoers file locks you out of sudo entirely.

Group membership only applies to new logins. If the alert panel still says it cannot read, restart
the manager.

## Why it asks for administrator

Hyper-V will not report VM state to an ordinary session. Rather than failing halfway, the script
relaunches itself elevated, so you get one UAC prompt at launch.

`-NoElevate` serves the page without it. The layout is all there but every VM reports "Needs
administrator", because Hyper-V is refusing to answer.

## It will not start your VMs by itself

Worth being precise, because it was a design requirement.

`New-Lab.ps1` creates every VM with `-AutomaticStartAction Nothing`, so Hyper-V will not start them
when the host boots, including if they were running when it shut down. The paired
`-AutomaticStopAction ShutDown` means a host restart shuts the guests down cleanly.

The dashboard reinforces that rather than trusting it:

- Each card shows its VM's live autostart setting and flags anything other than `Nothing`.
- "Lock: never autostart" sets all three to `Nothing`. The only value this code can write is
  `Nothing`; there is no path in it that enables automatic startup.
- Opening the page performs no action. Every change needs a click, including bringing the lab up.

All three running is 16 GB of fixed allocation: 8 manager, 6 Windows, 2 Linux. Memory is not
dynamic, so a running VM holds its full amount and an off VM holds none.

## What the buttons do

| Button | What happens |
| --- | --- |
| Start | `Start-VM`. Also resumes a saved VM. |
| Shut down | `Stop-VM`. Asks the guest to shut down cleanly. |
| Restart | `Restart-VM`. Clean guest restart. |
| Force off | `Stop-VM -TurnOff`. Cuts power immediately, like pulling the plug. |

Force off asks for confirmation. Use it only when a VM is unresponsive. Cutting power under the
manager can leave the indexer with a damaged shard, which is a slow problem to unpick. The
take-down sequence never uses it.

Actions run as background jobs, because a guest shutdown can take half a minute and the server is
single threaded. The page catches up on its next poll, and a failure appears on the page rather
than disappearing.

## Cost

A poll costs about 90 ms and runs every 3 seconds. It stops when the tab is hidden, so leaving
this open in a background tab costs nothing. There is also a Pause button.

Scoring rides inside that rather than beside it. It runs in the status script the manager was
already being sent, so there is no second round trip, no service and no open port. Twelve windows
of eleven features is a dot product and an exponential each: 4 ms for the manager's full 800
record sample, measured on this host, and some multiple of that on a 2 vCPU guest, against an SSH
round trip costing ten times more before any of it starts.

That is the whole argument for the model that won. Shipping PyTorch to a box whose job is
receiving alerts, to evaluate the model that lost on all eight folds, was never worth it.

The exception is a sequence in progress. The server advances it one step per request, so it only
moves while the page is asking; going quiet part way through a bring-up would leave it stalled mid
boot. Polling therefore continues while a sequence runs, and an unwatched gap is added back to the
phase deadline so that nobody looking is never reported as a timeout.

Four things were measured and fixed to get here, all worth knowing if you edit this:

**Host CPU comes from a performance counter, not `Win32_Processor`.** That WMI class takes about a
second to answer, which was most of the cost of every poll. The counter answers in about a
millisecond. Total memory is read once at startup because it does not change.

**Port probes use a non-blocking socket.** The obvious `BeginConnect` plus `WaitOne` version looks
like it honours its timeout and does not: against an unreachable host, `EndConnect` and `Close`
block until the operating system finishes its SYN retries. Measured against a powered-off lab VM
that turned a 400 ms timeout into a 21 second stall. Probes also only run against VMs that are
running, and are cached for 15 seconds, except during a sequence where the port coming up is the
thing being waited on.

**Health is gated on the SSH port probe, not on VM state.** Hyper-V reports Running the moment a
VM is powered on, roughly a minute before sshd answers, so gating on state alone spent an eight
second SSH timeout on every cycle of a cold boot.

**`Start-Process -PassThru` does not cache the process handle.** Once the process exits there is
nothing left to read an exit code from, so `ExitCode` comes back empty rather than 0, and
`$null -ne 0` is true. Every successful SSH call was being discarded as a failure. Reading
`.Handle` while the process is alive fixes it, and a genuine non-zero exit is still caught.

## How it reads the manager

One SSH round trip per cycle runs a Python script that returns service state, agent state, recent
alerts, coverage, ATT&CK tally, alert rate, log tail and disk as a single JSON document.

The script is sent, base64 encoded, rather than installed. Sending it means the dashboard works
with no setup step, and that changing what it reports is a change to this file alone; an installed
copy would have to be pushed out again every time and would go stale silently if it were not. It
is base64 encoded because passing shell inline through PowerShell to ssh mangles quoting, which
has already cost this project a corrupted file on the manager.

## Security

The listener binds `127.0.0.1` only, never `0.0.0.0`, so nothing on the network can reach it.

A random token is generated each run and injected into the page. Every API call must present it,
and no CORS headers are sent, so another site open in the same browser cannot read the token out
of the page or drive the API. Requests without the token get a 403.

The Windows scenario runner reads the console password from `.lab-secrets` at the moment of the
action and does not hold it. That is a plaintext password on disk. It already existed, it is
already gitignored, and it is already how this lab documents its console access, so nothing new is
exposed, but nothing is improved either.

The Lab access panel shows real passwords on request, on that same loopback-only, token-gated
page. They arrive masked. Worth being plain about what changed: before this, no Wazuh password
was read off the manager at all. Now one is, when you ask for it. The property kept is that it is
never an argument to anything and so never reaches a process list.

## If something goes wrong

**The page says there is no answer from the server.** The console window that launched it has
closed. Run `Lab.cmd` again.

**Every VM says "Needs administrator".** It is running unelevated. Close it, relaunch, and accept
the UAC prompt.

**Every VM says "Not found".** The VM names here no longer match the host. They are defined in one
table near the top of `Start-LabDashboard.ps1` and must match `New-Lab.ps1`.

**A bring-up gives up waiting for the services.** The manager booted but Wazuh did not start. SSH
in and read `systemctl status wazuh-indexer`, which is the one that fails first when the disk is
full or a shard is damaged.

**A VM will not shut down.** The guest is ignoring the request, usually because integration
services are not running or it is stuck at a boot prompt. Force off is the fallback.

**A panel says the manager cannot read this yet.** `Enable-LabDashboard.ps1` has not been run, or
was run before the last reboot and group membership has not taken effect. That message names
exactly which capability is missing.

**A scenario reports that it returned nothing.** It did not run. The most likely cause on Linux is
that the one-time setup has not been run on that endpoint; check with `sudo -l` as `labadmin`.

**The opening box says virtualization is off, but your VMs run.** Read the note under "Before it
opens". If `HypervisorPresent` is false on a host with running VMs, something is wrong with WMI
rather than with the firmware; Task Manager, Performance, CPU settles it in one look.
