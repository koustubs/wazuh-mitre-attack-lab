# Building the lab

Eight steps, each one script that does one job and says what it did. Nothing here installs a
hypervisor, and nothing runs on its own.

Everything reads `lab.config.json` at the root of the repository. Addresses, VM names, memory
and disk sizes, the Ubuntu image and the Wazuh version are all in that one file; change the
subnet there and every script and both guest images follow. Nothing below needs editing to
move the lab onto a different network.

## Choose a profile first

| | lean | full |
| --- | --- | --- |
| Host RAM | 8 GB | 16 GB |
| Free disk | 60 GB | 180 GB |
| Guests | manager, Linux endpoint | plus the Windows endpoint |
| Detection cases | 3 of 6, Linux only | 6 of 6 |
| Images to supply | none | a Windows 11 ISO |
| Manager | 4 GB, 2 vCPU, 32 GB disk | 6 GB, 4 vCPU, 60 GB disk |
| Linux endpoint | 1 GB, 1 vCPU, 16 GB disk | 1.5 GB, 2 vCPU, 20 GB disk |
| Windows endpoint | absent | 4 GB, 2 vCPU, 64 GB disk |

Host RAM is what the guests can grow to between them: the lean profile starts them at 5 GB and
caps them at 8, the full profile at 11.5 GB and 16. Whatever else the host runs comes on top.

Memory is dynamic on Hyper-V, with the minimum and maximum above in `lab.config.json`, so an
idle guest gives its unused pages back. VirtualBox has no equivalent and takes what it is
given.

The shipped profile is `full`. Set `"profile": "lean"` in `lab.config.json`, or pass
`-Profile lean` to any of the scripts below.

## Names and addresses

The network has no DHCP, so every guest has a static address written into its seed.

| Machine | VM name | Host name inside the guest | Address |
| --- | --- | --- | --- |
| Host | n/a | n/a | 172.29.70.1 |
| Manager | WAZUH-MANAGER | `wazuh-manager` | 172.29.70.10 |
| Windows endpoint | WAZUH-WIN | `WAZUH-WIN` | 172.29.70.20 |
| Linux endpoint | WAZUH-LINUX | `wazuh-linux` | 172.29.70.30 |

`install-manager.sh` opens port 1514 only to .20 and .30, so these are requirements rather
than suggestions. They come from `lab.config.json`, which is also where to change them.

---

## 0. Check the machine

```
.\setup\Test-LabHost.ps1
```

Changes nothing. It reports virtualization in firmware, under the name the CPU uses, which
hypervisors are usable here, whether Hyper-V and VirtualBox are in conflict,
RAM and disk against the profile, and whether the host can reach the internet. Each failure
prints the one command that fixes it. `-Profile lean` asks whether the smaller profile would
fit instead; `-Json` gives the same answers to a script.

Exit code 0 means nothing failed. Warnings do not fail it.

A missing hypervisor has to be installed first, and this does not do it. It prints the
`Enable-WindowsOptionalFeature` line for Hyper-V, or where to get VirtualBox. Enabling Hyper-V
costs a reboot and changes how the host runs, which is not a script's decision to make.

## 1. Create the lab credentials

```
.\setup\New-LabSecrets.ps1
```

Writes an SSH keypair, a 20 character console password and its SHA-512 crypt hash into
`.lab-secrets\`, which is gitignored and has never been committed. Everything downstream reads
those and fails immediately if they are missing.

It will not overwrite an existing set without `-Force`, because replacing the keypair locks out
every VM already built against the old one.

## 2. Fetch the Ubuntu image

```
.\setup\Get-LabImage.ps1
```

About 600 MB, from `cloud-images.ubuntu.com`. It fetches the published `SHA256SUMS`, checks the
signature when `gpg` is on the machine, downloads beside the target rather than onto it, and
deletes anything whose hash does not match instead of keeping it. Then it converts it to
whatever the backend boots.

This is a disk that has already been installed, so there is no Ubuntu ISO to source and no
operating system installer to sit through. Preparing it wants about 8 GB free for a couple of
minutes and takes a little over two on a desktop SSD. Everything lands under `storageRoot`,
beside the VM disks, not inside the clone. Run it once.

Both backends take the same generic cloud image. Hyper-V cannot read its QCOW2 container, so
`setup\QcowImage.ps1` reads it and writes the contents into a VHD. Canonical's ready-made
Azure VHD would have saved that work and cannot be used: it pins `datasource_list` to `Azure`,
so it ignores the NoCloud seed this lab hands it and boots with no address and no key.

## 3. Build the seeds

```
.\setup\New-LabSeeds.ps1
```

Builds the cloud-init seed ISOs for the Ubuntu guests: the account, the SSH key, the host name,
the static address, and `/etc/wazuh-lab/lab.env`, which is `lab.config.json` rendered as shell
assignments so the guest scripts read the same values the host does.

For the full profile, also:

```
.\setup\New-WindowsSeed.ps1
```

Builds the Windows unattend seed. Windows is the one guest that still installs from an ISO.
The free **Windows 11 Enterprise evaluation** image works, needs no product key and is the
easy option; it is a single-edition ISO, so leave `-ImageName` and `-ProductKey` unset. For a
multi-edition retail or VL ISO, pass `-ImageName` with the edition as the image list names it,
or Setup stops on the edition picker and waits for a human. Microsoft's generic Volume License
Setup Key for Windows 11 Pro selects the edition and activates nothing; pass it as
`-ProductKey` if the ISO needs one. An unactivated guest is fine for a lab that gets deleted.

## 4. Create the VMs

```
.\setup\New-Lab.ps1
```

Elevated. Creates the network, the VMs for the profile, and attaches the boot disk and the seed
to each. Add `-WindowsIso <path>` on the full profile.

The Ubuntu guests boot the image from step 2 and configure themselves from the seed on first
boot, which takes seconds rather than the fifteen minutes an installer took.

The Windows guest still boots an installer, and its first boot is a script rather than a power
button:

```
.\setup\Start-WindowsInstall.ps1
```

Windows media, retail and evaluation alike, shows `Press any key to boot from CD or DVD` for
about five seconds. Unpressed, the boot manager hands back to the firmware, which reports `The
boot loader failed` against the DVD and falls through to a disk with no operating system on it
yet. The guest then sits there having written nothing, and no log on either side says why. That
script starts the VM and presses the key across the whole window rather than at a guessed point
in it, and Setup runs unattended from there: two reboots, about twenty minutes, nothing else to
press. Later boots need none of it, because the installed disk sits behind the ISO in the boot
order, so the prompt lapses and the firmware moves on to Windows.

Nothing autostarts. The VMs are created stopped, and the only autostart value the dashboard can
write is `Nothing`, because three VMs waking up on login is 11 GB of somebody else's RAM.

## 5. Install the manager

The manager scripts are not in the guest, so copy them across and run them there. From the
repository root:

```
scp -i .lab-secrets\lab_ed25519 -r manager labadmin@172.29.70.10:~/
ssh -i .lab-secrets\lab_ed25519 labadmin@172.29.70.10
```

Then, on the manager:

```
sudo bash manager/install-manager.sh
sudo bash manager/configure-manager.sh
sudo bash manager/configure-dashboard.sh
```

The first installs manager, indexer and dashboard, pinned to the version in
`lab.config.json`. Before it installs anything it runs `configure-firewall.sh` from beside it,
which opens 22 and 443 to the host and 1514 to each endpoint the profile builds and denies
everything else. After the install it runs `tune-manager.sh`, also from beside it: indexer heap
sized to the profile, vulnerability detection off since this lab never queries the feed it
downloads, syscollector lengthened, and a 90-day deletion policy so the alert indices do not
grow without bound. Copy the whole `manager` directory rather than the one file. The firewall
step is a hard failure if it is missing, because installing Wazuh with nothing in front of it is
worse than not installing it. Tuning failures leave the completed Wazuh installation in place
and print that tuning is incomplete. Re-run `sudo bash manager/tune-manager.sh` after resolving
the reported error. Its `configure-retention.py` helper must remain beside it.

Retention waits for yellow cluster health, retries temporary ISM failures, and reads back the
policy attachments before reporting success. A failed lookup or attachment returns a nonzero
status rather than being reported as an index with nothing to do.

An existing policy whose settings differ is reported and left alone rather than overwritten, so
changing `LAB_ALERT_RETENTION_DAYS` is a deliberate two step. Delete the old policy, then re-run
tuning:

```
sudo curl -sk --cert /etc/wazuh-indexer/certs/admin.pem      --key /etc/wazuh-indexer/certs/admin-key.pem -X DELETE      https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-lab-retention
sudo bash manager/tune-manager.sh
```

Indices already attached to the deleted policy keep their old age condition until the new policy
is attached, which the re-run does.

### Changing profile on a manager that is already built

Two things on the manager come from the profile and neither updates itself. Going from lean to
full adds a Windows endpoint at .20, and until both are re-run the agent will not enrol and will
not check in, with nothing in the manager's logs to say why, because the packets never arrive.

```
scp -i .lab-secrets\lab_ed25519 -r manager labadmin@172.29.70.10:~/
ssh -i .lab-secrets\lab_ed25519 labadmin@172.29.70.10
```

```
sudo bash manager/configure-firewall.sh
sudo bash manager/configure-manager.sh
```

The first opens 1514 to the endpoints the new profile builds and closes it to any it no longer
does. The second adds an agent identity for each new endpoint and leaves existing ones alone.
Both are idempotent. The guest reads the profile from `/etc/wazuh-lab/lab.env`, which is written
from `lab.config.json` into the seed, so a guest built under the old profile still holds the old
one: regenerate it with `setup\Write-GuestConfig.ps1` and copy it to
`/etc/wazuh-lab/lab.env` first, or both scripts will faithfully re-apply the profile being
left behind.

The second deploys `lab_rules.xml`, validates it, disables `authd`, and writes one agent
identity per endpoint into `/root/wazuh-lab-keys/`.

The third creates the `wazuh-alerts-*` index pattern and makes it the default. Do not skip it.
Wazuh does not create an index pattern during installation; it is created the first time
somebody opens the web UI. A lab built entirely over SSH otherwise ends up with a working
detection pipeline and a dashboard that renders nothing, which is easy to mistake for a
detection failure.

## 6. Enrol the endpoints

```
.\setup\Install-LabAgents.ps1
```

For each endpoint in the profile: collect its key from the manager, copy the key and the
installer across, and run the installer there. The key never touches the repository and is
deleted from this host as soon as it has been delivered. `-Only WAZUH-LINUX` does one of them.

The privileged install on the endpoint asks for the console password. Have it ready: the
dashboard's credentials panel shows it, or it is in `.lab-secrets\console-password.txt`.

On Linux this installs the agent, the auditd rules keyed `wazuh_lab_cron`, and realtime
monitoring on the cron directories. Wait for the first file integrity scan to finish before
testing S3, or the cron change has no baseline to compare against.

On Windows it enables three audit subcategories that are off by default. Without them the
events are not written at all:

| Subcategory | Setting | Gives |
| --- | --- | --- |
| Logon | failure | 4625 |
| User Account Management | success | 4720 |
| Other Object Access Events | success | 4698 |

The existing policy is backed up to `%ProgramData%\WazuhLab` first.

## 7. Let the dashboard read the manager

```
.\dashboard\Enable-LabDashboard.ps1
```

Run once, after the lab is built. It installs three root-owned helpers on the manager and one
sudoers rule granting the lab account exactly those commands and nothing else: the agent list,
an authenticated search against the indexer over its admin certificate, and the per-endpoint
baseline the scoring divides by. Without it the dashboard still works and says which of those
it cannot read. See `dashboard/README.md`.

## 8. Checkpoint the endpoints

S2 and S3 create local accounts and scheduled jobs. The scenario scripts clean up after
themselves on every exit path, but a checkpoint is the reliable reset. Take it while the
endpoints are shut down, so it holds a disk state and no saved memory, from an elevated prompt:

```
Checkpoint-VM -Name WAZUH-LINUX, WAZUH-WIN -SnapshotName clean
```

With VirtualBox:

```
VBoxManage snapshot WAZUH-LINUX take clean
VBoxManage snapshot WAZUH-WIN take clean
```

The lean profile has no `WAZUH-WIN`. To go back, with the endpoint shut down,
`Restore-VMSnapshot -VMName WAZUH-LINUX -Name clean` or
`VBoxManage snapshot WAZUH-LINUX restore clean`.

---

## Running the scenarios

From the dashboard, or on the Linux endpoint after step 7:

```
sudo lab-scenario S1 test
sudo lab-scenario S1 comparison
sudo lab-campaign start 14
```

and on the Windows endpoint, from an elevated prompt:

```
.\Invoke-Scenario.ps1 -Scenario S1            # and S2, S3
.\Invoke-Scenario.ps1 -Scenario S1 -Comparison
```

`lab-scenario` and `lab-campaign` are wrappers step 7 installs, and the sudoers rule names
the exact invocations they accept rather than the script, so the dashboard can start one
without a password and nothing else can be run through the grant.

Every scenario performs a real action and then verifies the OS-native event exists, failing
loudly if it does not. S1 on Linux stands up a throwaway `sshd` and drives real authentication
at it; on Windows it calls `LogonUser` and asserts the error is 1326. S2 is a real `useradd`
or `New-LocalUser`, S3 a real `/etc/cron.d` write or `Register-ScheduledTask`. Nothing is
injected into a log.

Comparison mode is the benign case. For S1 it makes a single failed logon, which is below the
alert threshold. For S2 and S3 it performs the same action and records it as approved activity,
because the point of those two is that the behaviour is ambiguous and needs an analyst, not
that it is inherently malicious.

Each run writes source events and a `run.json` to an evidence directory. `indexedDetection`
stays `not_checked` until the matching alert is confirmed in the dashboard, so a run is not
evidence of detection on its own.

## Running the lab day to day

`Lab.cmd`, at the root of the repository, is the front door. It opens the dashboard in the default
browser, and that is where the lab is started, watched and stopped from. It asks for elevation
once at launch, because the hypervisor will not report VM state otherwise.

The page runs the same preflight as step 0 before it opens, so anything blocking is named along
with the command that fixes it. It also shows the logins for the Wazuh web interface and for
every guest in the profile, with the passwords masked until asked for.

"Bring the lab up" starts the manager, waits for it to boot and for the four Wazuh services to
come up, then starts the endpoints and waits for the agents to check in. "Take the lab down"
reverses it, endpoints first and the manager last, so the indexer is the final thing to close.

Opening the dashboard is read-only. It will not start anything by itself.

## Taking it apart

```
.\setup\Remove-Lab.ps1                 the VMs and the network, disks left alone
.\setup\Remove-Lab.ps1 -DeleteDisks    and the disks
.\setup\Remove-Lab.ps1 -KeepNetwork    the VMs only
```

Nothing under `.lab-secrets` or `evidence` is touched, and the keys still work against a
rebuilt lab because the seeds carry the same public key.

## Worth knowing

S1 makes exactly six failed attempts and rule 100111 fires at six. That is deliberate, since
the five-attempt case has to stay below the threshold, but it means the run has no spare
margin. If an alert does not appear, check the captured source event count first; the scripts
verify those events exist and fail loudly if they are short.
