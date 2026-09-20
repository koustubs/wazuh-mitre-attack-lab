# Collecting a labelled dataset

The six rules in this lab fire on single events in isolation. Anything that reasons about
*patterns*, whether that is a sequence model over rule ids or a baseline of what normal looks
like per user, needs examples to learn from, and the lab has nine recorded runs. That is a
handful, not a dataset.

`04-implementation/linux/run-campaign.sh` turns one run into a night of them.

> **Read this next to the public data first.** A campaign is no longer the only way to get
> numbers. `05-detection-modelling/import-ait.py` brings in 2.6 million labelled Wazuh alerts
> from eight networks, which is what the modelling results are now measured on, and it took an
> afternoon rather than a night.
>
> That does not make a campaign optional, because the two answer different questions. The
> public data has none of our rules in it: no sshd brute force, no account creation, no FIM,
> and 5501 and 5502 are the whole overlap. So it can say whether reading a sequence of alerts
> beats counting them, and only a campaign can say whether **these** rules separate an attacker
> from an administrator. Run one when that is the question being asked, rather than to get a
> model trained.

## What it produces

A campaign is a run of several hours made of **episodes**. An episode is one intent carried out
over one or more scenario runs, and the label belongs to the episode rather than to any single
run, so a three step intrusion is one labelled sample that produced several alerts.

| Episode | Label | What it does |
| --- | --- | --- |
| `admin-failed-login` | benign | S1 with 1 to 5 failed logons |
| `admin-new-account` | benign | S2 |
| `admin-new-cronjob` | benign | S3 |
| `admin-provision` | benign | S2 then S3, 1 to 5 minutes apart |
| `bruteforce` | attack | S1 with 6 to 14 failed logons |
| `bruteforce-persist` | attack | S1 then S2 then S3, 15 to 75 seconds apart |
| `quiet-persist` | attack | S2 then S3, 10 to 45 seconds apart |

Underneath the episodes, three standing accounts (`labstaff1` to `labstaff3`) open ordinary
login sessions every 20 to 60 seconds. They have different shapes on purpose: one is present
the whole run, one only in the first seven hours, one is rare. Without them, normal in the
dataset would mean *no events at all*, and a model trained on that has learned nothing useful.
They are created before recording starts and removed when the campaign ends.

## Two constraints that shaped it

**Rule 100111 is `frequency="6" timeframe="120"`.** Two S1 runs closer together than the
timeframe share a counting window, so failures from the first are counted towards the second
and a benign run can be swept into a composite alert it did not cause. That is a wrong label
going into training data, which is worse than having less of it. The runner holds S1 runs at
least 150 seconds apart and says so in the log when it waits.

**The same threshold constrains the labels.** `comparison` takes 1 to 5 failed logons and
`test` takes 6 or more. `invoke-scenario.sh` now rejects any other pairing outright rather than
producing a run whose label does not describe the alert.

## Running one

Simulate first. This needs no root, touches nothing, and prints the pacing and the label mix:

```bash
bash run-campaign.sh simulate 14
```

A 14 hour campaign comes out at roughly 170 episodes, 250 runs and 1000 background ticks, about
64% benign.

On the VM:

```bash
sudo bash run-campaign.sh start --hours 14
```

It detaches, so closing the SSH session does not stop it. Recording begins after a three minute
pause, which keeps the standing accounts' own creation alerts outside the window.

```bash
sudo bash run-campaign.sh status
sudo bash run-campaign.sh stop
```

`stop` finishes the episode in flight, removes the standing accounts and exits cleanly.

On the host, beside it:

```powershell
.\04-implementation\host\Sync-LabCampaign.ps1 -Watch
```

## Picking the window

Only the manager and the Linux endpoint are needed, so this is 10 GB rather than 16. Leave the
Windows VM off.

The overnight risks are not the ones people expect. Check them in this order:

1. **Host sleep and hibernate.** A desktop quietly sleeping at 2am is far more likely than a
   power cut. Confirm with `powercfg /q SCHEME_CURRENT SUB_SLEEP`; both should read Never.
2. **Windows Update restarting the host.** Updates do not restart during active hours. Read
   yours from `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`, then pick a window that sits
   entirely inside them.
3. **A pending reboot.** Reboot before starting rather than during.

Host activity does not affect the data. The VMs have fixed memory rather than dynamic, so the
lab keeps its allocation whatever else is running, and the labels come from the argument each
run was called with, not from timing. A busy host makes timestamps noisier, nothing worse.

## Losing power

Every record is appended the moment its run finishes, and `Sync-LabCampaign.ps1 -Watch` copies
them to the host as they arrive. So a power cut costs the run in flight and nothing before it,
and the dataset survives on the host even if the indexer comes back needing a shard repair.

A line truncated mid-write is discarded by every reader here rather than guessed at. A campaign
that dies is simply over; start a new one, and read the union of the campaign directories.
There is no resume, because append-only files do not need one.

## What this data can and cannot support

Worth being straight about, because it belongs in any write-up of what gets trained on it.

The labels are whatever the campaign decided to do, not a judgement made about the events
afterwards. The separability built into the generator is exactly two things: an attacker brute
forces before persisting, and moves between steps in seconds where an administrator takes
minutes. Both are true of real intrusions. But a model that scores well here has learned those
two things, and a good result is evidence that the pipeline works, not that the model would
catch a real intruder.

`admin-provision` and `quiet-persist` are the same two scenarios in the same order and differ
only in the gap between them. That pair is deliberately the hard case, and it is the one worth
looking at when judging whether a model learned anything beyond counting.

The other honest limit is that this is one host with three standing accounts and three scenario
shapes. It is enough to build and measure a pipeline against. It is not a sample of the world.
