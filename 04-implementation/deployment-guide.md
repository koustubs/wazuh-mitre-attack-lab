# Deployment guide

Build order for the Hyper-V lab. `New-Lab.ps1` refers to this document.

The scripts check the machine they are running on and stop if it is the wrong one. Those checks
are strict, so the names and addresses below are requirements, not suggestions.

## Before starting

- Windows 11 ISO and Ubuntu Server 24.04 ISO on disk.
- An elevated PowerShell session. `New-Lab.ps1` declares `#requires -RunAsAdministrator` and
  `Get-VMSwitch` fails without it.
- Around 220 GB free on the target drive. Use D:, since C: is short on space.

## Names and addresses

The switch is Internal with NAT and has no DHCP server, so every guest needs a static address.
Getting these wrong is the most likely reason a script refuses to run.

| Machine | VM name | Host name inside the guest | Address |
| --- | --- | --- | --- |
| Host | n/a | n/a | 172.29.70.1 |
| Manager | WAZUH-MANAGER | `wazuh-manager` | 172.29.70.10 |
| Windows endpoint | WAZUH-WIN | `WAZUH-WIN` | 172.29.70.20 |
| Linux endpoint | WAZUH-LINUX | `wazuh-linux` | 172.29.70.30 |

Gateway 172.29.70.1, prefix /24. The endpoint addresses are fixed by the firewall rules in
`install-manager.sh`, which only opens port 1514 to .20 and .30.

The guest host name is set during operating system installation and is not the same as the
Hyper-V VM name. Setting only the VM name is the easy mistake here.

## Steps

**0. Create the lab credentials.** Nothing else works without them, and a fresh clone has none.

```
.\host\New-LabSecrets.ps1
```

This writes the SSH keypair, the console password and its SHA-512 crypt hash into
`host\.lab-secrets\`, which is gitignored. Both seed builders in the next step read those files
and fail immediately if they are missing. It refuses to overwrite an existing set without
`-Force`, because replacing the key locks you out of any VM already built with it.

**1. Create the VMs.** From an elevated prompt:

```
.\host\New-Lab.ps1 -UbuntuIso <path> -WindowsIso <path> -StorageRoot D:\Wazuh-Lab
```

This creates the switch, the NAT, and three Generation 2 VMs. The Windows VM gets a key
protector, TPM and Secure Boot, which Windows 11 requires.

**2. Install Ubuntu on WAZUH-MANAGER.** Host name `wazuh-manager`, static 172.29.70.10, OpenSSH
enabled. The manager needs outbound internet through the NAT to fetch the Wazuh installer.

**3. Install and configure the manager.**

```
sudo bash manager/install-manager.sh
sudo bash manager/configure-manager.sh
sudo bash manager/configure-dashboard.sh
```

The first installs manager, indexer and dashboard and pins them to 4.14.7. The second deploys
`lab_rules.xml`, validates it, disables `authd`, and writes one agent identity per endpoint into
`/root/wazuh-lab-keys/`. All three refuse to run anywhere except the manager host.

The third creates the `wazuh-alerts-*` index pattern and makes it the default. Do not skip it.
Wazuh does not create an index pattern during installation: it is created the first time somebody
opens the web UI. A lab built entirely over SSH therefore ends up with a working detection
pipeline and a dashboard that renders nothing at all, which is easy to mistake for a detection
failure.

**4. Install Ubuntu on WAZUH-LINUX.** Host name `wazuh-linux`, static 172.29.70.30.

**5. Configure the Linux agent.** Copy `wazuh-linux.key` from the manager over SSH, then:

```
sudo bash linux/install-agent.sh 172.29.70.10 ./wazuh-linux.key
```

This installs the agent, auditd rules keyed `wazuh_lab_cron`, and realtime file monitoring on the
cron directories. Wait for the first file integrity scan to finish before testing S3, otherwise
the cron change has no baseline to compare against.

**6. Install Windows on WAZUH-WIN.** Computer name `WAZUH-WIN`, static 172.29.70.20.

**7. Configure the Windows agent.** Copy `wazuh-windows.key` across, then from an elevated
prompt:

```
.\windows\Install-Agent.ps1 -ManagerAddress 172.29.70.10 -AgentKeyFile .\wazuh-windows.key
```

This enables three audit subcategories that are off by default. Without them the events simply
are not written:

| Subcategory | Setting | Gives |
| --- | --- | --- |
| Logon | failure | 4625 |
| User Account Management | success | 4720 |
| Other Object Access Events | success | 4698 |

The existing policy is backed up to `%ProgramData%\WazuhLab` first.

**8. Confirm both agents report as active** in the manager before running anything.

**9. Take a checkpoint of each endpoint.** S2 and S3 create local accounts and scheduled jobs.
The scripts clean up after themselves, but a checkpoint is the reliable reset.

## Running the scenarios

```
.\windows\Invoke-Scenario.ps1 -Scenario S1            # and S2, S3
.\windows\Invoke-Scenario.ps1 -Scenario S1 -Comparison

sudo bash linux/invoke-scenario.sh S1 test
sudo bash linux/invoke-scenario.sh S1 comparison
```

Comparison mode is the benign case for R4. For S1 it makes a single failed logon, which is below
the alert threshold. For S2 and S3 it performs the same action and records it as approved
activity, because the point of those scenarios is that the behaviour is ambiguous and needs an
analyst, not that it is inherently malicious.

Each run writes source events and a `run.json` to an evidence directory. `indexedDetection` stays
`not_checked` until the matching alert is confirmed in the dashboard, so a run is not evidence of
detection on its own.

## Running the lab day to day

`Lab.cmd`, at the root of the repository, is the front door. It opens the dashboard in your
browser, and that is where the lab is started, watched and stopped from. It asks for elevation
once at launch, because Hyper-V will not report VM state otherwise.

The page checks the machine before it opens: virtualization enabled in firmware, the Hyper-V
platform live, the switch and NAT, all three VMs, `.lab-secrets`, and an SSH client. Anything
blocking is named along with the command that fixes it. It also shows the logins for the Wazuh
web interface and all three guests, with the passwords masked until asked for.

"Bring the lab up" starts the manager, waits for it to boot and for the four Wazuh services to
come up, then starts both endpoints and waits for the agents to check in. "Take the lab down"
reverses it, endpoints first and the manager last, so the indexer is the final thing to close.

It will not start anything by itself. Opening it is read-only, and the only autostart value it can
write is `Nothing`.

Run `host/lab-dashboard/Enable-LabDashboard.ps1` once, after the lab is built, so the dashboard
can also read alerts, agent state and the indexer. Without it the dashboard still works and says
which of those it cannot read. See `host/lab-dashboard/README.md`.

## Worth knowing

S1 makes exactly six failed attempts and rule 100111 fires at six. That is deliberate, since the
five-attempt case has to stay below the threshold, but it means the run has no spare margin. If
an alert does not appear, check the captured source event count first. The scripts verify those
events exist and fail loudly if they are short.
