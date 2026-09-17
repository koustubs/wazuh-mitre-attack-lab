# Lab dashboard

A monitor for the lab. It shows what the lab is doing and what it is costing, and keeps the
controls out of the way until you ask for them.

This is not how the lab gets built or started. Follow `deployment-guide.md` for that. This runs
afterwards, once everything is up.

## What it shows

Three panels, in the order you usually want them.

**Lab health.** Every Wazuh service on the manager, and whether each agent is checking in, as a
green or red dot. Agent state is reported by the manager rather than gathered from the endpoints,
which is why the Windows machine never has to be contacted.

**Recent alerts.** The newest detections in plain rows: time, agent, rule, level, description and
ATT&CK technique. Level 10 and above is coloured. A dropdown narrows the list to 5, 10, 15, 25 or
50 and remembers your choice. The manager always sends 50, so changing that figure redraws
instantly instead of going back over SSH for a shorter list. This is the panel that tells you at
a glance whether the project is working, without loading the full Wazuh web interface.

**Virtual machines.** Live CPU, memory and uptime per VM, its autostart setting, which ports are
answering, and start, shut down, restart and force off.

Above all three is a host strip: CPU, memory, how much the lab is using, and free space per drive.

## Advanced

The toggle in the top right corner. Off by default, and remembered between visits.

Turning it on adds start, stop and restart buttons to every individual Wazuh service, a restart
button for the Linux agent, and a Lab actions panel with the autostart lock, shut down all, and
stop dashboard.

The point of the split is that the normal view should be readable at a glance. Nothing in the
default view can stop a service by accident.

## Running it

Double-click **`Lab dashboard.cmd`**, accept the elevation prompt, and the page opens in your
browser.

That is the whole thing. There is nothing to install: it uses the Hyper-V module, CIM and
`System.Net.HttpListener`, all of which ship with Windows.

A console window stays open while the dashboard runs. Leave it there. Closing it, or clicking
"Stop dashboard" on the page, shuts the server down. Neither touches the VMs.

If port 8077 is busy:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-LabDashboard.ps1 -Port 9000
```

## One-time setup for health and alerts

The VM panel works immediately. The Lab health and Recent alerts panels need one setup pass,
because they read from inside the manager over SSH.

With the lab running:

```
.\Enable-LabDashboard.ps1
```

It asks for the lab account's sudo password once, uses it for that run, and stores nothing. It
installs three things:

- `/usr/local/bin/lab-dashboard-status` on the manager, which returns service state, agent state
  and recent alerts as a single JSON document. One SSH round trip per cycle rather than several.
- Membership of the `wazuh` group for `labadmin`, so the alert log is readable without sudo.
  Reading alerts is the main thing this dashboard does and it should not need root to do it.
- A sudoers drop-in permitting exactly `systemctl start`, `stop` and `restart` on the named Wazuh
  units, plus `agent_control -l`. Nothing else. It is checked with `visudo` first, and if
  validation fails nothing is written, because a broken sudoers file locks you out of sudo
  entirely.

After this the dashboard never needs a password again. This also removes the "re-stage the sudo
password" chore recorded in `PROJECT-STATUS.md`.

Group membership only applies to new logins. If the alert panel stays empty straight afterwards,
restart the manager.

## Why it asks for administrator

Hyper-V will not report VM state to an ordinary session, which is not something the script can
work around. Rather than failing halfway through, it relaunches itself elevated so you get one
UAC prompt at launch.

To look at the page without elevating, add `-NoElevate`. The layout is all there but every VM
reports "Needs administrator", because Hyper-V is refusing to answer.

## It will not start your VMs by itself

This was a design requirement, so it is worth being precise.

`New-Lab.ps1` creates every VM with `-AutomaticStartAction Nothing`, which means Hyper-V will not
start them when the host boots, including if they were running when it shut down. The paired
`-AutomaticStopAction ShutDown` means a host restart shuts the guests down cleanly rather than
freezing them to disk.

The dashboard reinforces that rather than trusting it:

- Each card shows its VM's live autostart setting, and flags anything other than `Nothing`.
- "Lock: never autostart" under Advanced sets all three to `Nothing`. The only value this code
  can write is `Nothing`; there is no path in it that enables automatic startup.
- Opening the page performs no action at all. Every change needs a click.

All three VMs running is 16 GB of fixed allocation, 8 for the manager, 6 for Windows, 2 for
Linux. Memory is not dynamic, so a running VM holds its full amount and an off VM holds none.

## What the buttons do

| Button | What happens |
| --- | --- |
| Start | `Start-VM`. Also resumes a saved VM. |
| Shut down | `Stop-VM`. Asks the guest to shut down cleanly. |
| Restart | `Restart-VM`. Clean guest restart. |
| Force off | `Stop-VM -TurnOff`. Cuts power immediately, like pulling the plug. |

Force off asks for confirmation. Use it only when a VM is unresponsive. Cutting power under the
manager can leave the indexer with a damaged shard, which is a slow problem to unpick.

Buttons enable and disable themselves from the VM's state, and everything locks while a VM is
mid-transition, so you cannot stack conflicting actions.

Actions run as background jobs, because a guest shutdown can take half a minute and the server is
single threaded. The page catches up on its next poll. If a job fails, the error appears on the
page rather than disappearing.

## Reachability dots

Under each running VM the page shows whether known ports answer: 443 and 22 on the manager, 22 on
the Linux endpoint.

The Windows endpoint deliberately shows nothing to check. Its firewall drops inbound connections
by default and its agent connects outbound to the manager, so silence there is correct and is not
a sign of a problem.

## Cost

A poll costs about 175 ms and runs every 3 seconds, and stops completely when the browser tab is
hidden, so leaving it open in a background tab costs nothing. There is also a Pause button.

Two things were measured and fixed to get there, both worth knowing if you edit this:

**Host CPU comes from a performance counter, not `Win32_Processor`.** That WMI class takes about
a second to answer, which was most of the cost of every poll. The counter answers in about a
millisecond. Total memory is read once at startup because it does not change.

**Port probes use a non-blocking socket.** The obvious `BeginConnect` plus `WaitOne` version looks
like it honours its timeout and does not: against an unreachable host, `EndConnect` and `Close`
block until the operating system finishes its SYN retries. Measured against a powered-off lab VM
that turned a 400 ms timeout into a 21 second stall. Probes also only run against VMs that are
actually running, and are cached for 15 seconds.

## Security

The listener binds `127.0.0.1` only, never `0.0.0.0`, so nothing on your network can reach it.

A random token is generated each run and injected into the page. Every API call must present it,
and no CORS headers are sent, so another site open in the same browser cannot read the token out
of the page or drive the API. Requests without the token get a 403.

## If something goes wrong

**The page says there is no answer from the server.** The console window that launched it has
closed. Run `Lab dashboard.cmd` again.

**Every VM says "Needs administrator".** It is running unelevated. Close it and relaunch, and
accept the UAC prompt this time.

**Every VM says "Not found".** The VM names in this script no longer match the host. They are
defined in one table near the top of `Start-LabDashboard.ps1` and must match `New-Lab.ps1`.

**A VM will not shut down.** The guest is ignoring the request, usually because integration
services are not running or it is stuck at a boot prompt. Force off is the fallback.

**Lab health says there is no answer over SSH.** Either the manager is still booting, or
`Enable-LabDashboard.ps1` has not been run yet. The panel says which it suspects.

**Recent alerts is empty but services are green.** Most likely `labadmin` is not yet in the
`wazuh` group for its current session, so the alert log is unreadable. Restart the manager. If it
is still empty, the lab genuinely has not produced alerts in the window being read.

**Service buttons fail with "check that the one-time setup has been run".** The sudoers drop-in is
missing or was rejected by `visudo`. Run `sudo -l` as `labadmin` on that VM to see what is
actually permitted.
