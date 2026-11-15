# 0051. Two lanes of work, and an isolated machine for suspect apps

- Status: Proposed
- Date: 2026-11-15
- Decided by: the maintainer, 2026-11-15, that normal work goes on as before and that sensitive security work runs
  only in an isolated machine, on a separate account verified for defensive security work, with the AI agent itself
  saying so when it reaches such work; the decisions below are proposed, drafted with AI help.
- Builds on: ADR [0048](0048-lab-probe-of-android-gaps.md) (decision 4, the routes for a finding) and
  [LAB.md](../LAB.md).
- Follows: Anthropic's "Agent containment best practices for CVP participants" (2026-10-06).

## Context

Datapavan is built with AI agents (Claude Code) on the maintainer's own workstation. That machine also holds other
projects, SSH and commit-signing keys, browser profiles and a mail store, and its emulators and the lab phones share
the home network. For the work so far, the project's own code, builds and tests, that is acceptable: every agent
action is reviewed before it runs (Claude Code's auto mode), and since 2026-11-15 the project's local settings make
auto mode the default and switch bypass mode off for this project.

Work that is coming is of another kind. Watch and the audit need to know what fake or repackaged VPN and proxy apps,
apps from owners nobody can identify, and tracker SDKs actually do (DESIGN.md, and the maintainer's private incident register), and reported
flaws in messengers and circumvention tools need triage. That means installing and running hostile code, and asking an
agent to analyse it, sometimes with the model provider's default cyber safeguards relaxed for a verified account. Two
risks follow: hostile code on the workstation or its network, and an agent acting beyond the intended scope.

Anthropic's guide for such work asks for:
- **Isolation:** a virtual machine or a dedicated host, with egress blocked except the model API, reached through a
  proxy; every tool installed before a run, so nothing is fetched during it.
- **A test before live runs:** with a new sandbox or model, the model probes the sandbox and tries to escape it, under
  close human supervision and without internet, and stops and reports if it succeeds.
- **Records:** transcripts and the sandbox's egress log kept at least 30 days, runs with denied or unexpected egress
  reviewed, and out-of-scope behaviour reported to Anthropic.
- **Scope as intent:** "do not contact hosts outside X" rather than "you cannot reach the internet", so the instruction
  holds when the environment is misconfigured.
- **Auto mode,** with the environment and targets described in `autoMode.environment` rather than the mode switched
  off; and an engineer able to halt a run at once.

## Decision

### 1. Two lanes

- **Lane 1, normal work,** goes on as before, on the workstation, with any of the maintainer's accounts: the
  project's own code, builds and tests; emulator runs with the project's own apps and fixtures (gaps-probe included);
  documents, ADRs, research from public sources; static reading of open-source code.
- **Lane 2, sensitive work,** runs only inside the analysis machine (decision 3):
  - running, installing or decompiling apps the project did not build that are suspected of being hostile (fake or
    repackaged VPN and proxy apps, tracker SDK samples);
  - reproducing or testing a reported flaw;
  - dynamic analysis of a suspect app with its real traffic;
  - anything that needs the verified account's relaxed safeguards, or that the default safeguards stop.
- **An exception** needs the maintainer's word for that case, recorded with it. The studies already agreed on the
  maintainer's lab phone, of apps installed on it before, stay as they were agreed.

### 2. The machine is the check, and the agent says when it gets there

An agent cannot verify from inside a session which account it runs on. What it can verify is where it runs. So:
- the analysis machine carries a marker (decision 3), and only the verified account signs in there;
- lane-2 work starts only in a session that finds the marker;
- a session without it that reaches a lane-2 step stops that step, tells the maintainer in one line that the step is
  lane 2 and what it needs (the verified account, the machine ready, the scope written), writes a brief in the
  maintainer's private notes, and goes on with lane-1 work.
- The rule sits in the agents' standing notes for this project, which every session in its folders loads whatever
  the account, and in the maintainer's private notes beside the briefs. Claude Code's auto-mode classifier reads its
  environment text only from user or managed settings, never from a project's own files (so that a repository
  cannot widen its own permissions); a Datapavan section for it is drafted, and adding it is the maintainer's call
  (decision 9).

### 3. The analysis machine

- **A QEMU/KVM virtual machine (libvirt) on the workstation, not Firecracker.** Dynamic analysis needs the Android
  Emulator inside the machine, and the emulator needs KVM there: nested virtualization. Firecracker does not support
  nested virtualization; Cloud Hypervisor documents it but no report of the Android Emulator on it was found, so it is
  the fallback. Anthropic's own deployment guide puts QEMU beside Firecracker as a VM with excellent isolation when
  set up correctly.
- **Nested virtualization is the sharp edge:**
  - Android's documentation says a VM-accelerated emulator cannot run inside another VM; Google's own container
    scripts run it nested, more slowly. So the build starts with a pilot: the emulator must boot inside the machine
    with `-accel on` (which fails rather than falling back to slow emulation) and `/dev/kvm` present.
  - Nested KVM has had guest-to-host flaws: CVE-2026-53359 and CVE-2026-64561, both fixed in Debian's 7.2.15-1 kernel,
    the one the workstation runs. The workstation's kernel is kept current while lane 2 is in use, the SVM extension
    is offered to this machine only, and the machine's state is never saved while the emulator runs inside it (on
    AMD, saving a guest that runs its own guest is unsafe).
  - **If the pilot fails:** the fallback is the emulator on the workstation under a user of its own, in a network
    namespace whose only link is the sinkhole, driven from the machine over a forwarded adb port. That has no VM
    boundary around the emulator, so it needs the maintainer's word before it is used.
- **Inside the machine:**
  - **Marker:** a root-owned file, `/etc/datapavan-lane-2`, and a host name of the same meaning; a lane-2 session
    checks both before it starts.
  - **Two users:** `agent` runs Claude Code with the verified account's sign-in; `samples` owns the samples, the
    emulator and the tools that open them. The machine's own firewall lets only `agent` reach the model proxy.
  - **Tools:** installed from a pinned list when the image is built (jadx, apktool, androguard, the emulator and its
    system images, the sinkhole); nothing is fetched during a job.
- **Clean for each job:** after a job the machine is shut down and its disk overlay thrown away; the next job starts
  from the clean base image.
- **Size:** it takes the place of two emulators under the workstation's machine rule (up to 8 threads and 12 GB),
  and runs alone when a timing result depends on it.

### 4. Network: closed by default

The machine has no route of its own. Everything it sends reaches the workstation, whose firewall drops all of it
except what this decision lists, and logs both what it passes and what it drops (decision 7).

- **The model API,** through an HTTP proxy on the workstation that allows CONNECT only to the hosts Claude Code needs
  with a claude.ai sign-in: `api.anthropic.com` for the model, and `claude.ai`, `claude.com` and
  `platform.claude.com` for the sign-in and its refresh. The proxy does not intercept TLS. Inside the machine,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` is set, which turns off telemetry, error reports, feedback and
  automatic updates; Claude Code is updated by rebuilding the machine's image; the WebFetch and WebSearch tools are
  denied in the machine's own settings.
- **The suspect app's traffic,** in the mode the brief names:
  - **none:** static work; the app never runs, or runs with no network at all;
  - **sinkhole,** the default for dynamic runs: names are answered inside the machine and every connection ends at a
    catch-all that records it; nothing leaves the machine;
  - **exit,** only with the maintainer's word for that run: through a separate exit that is never the maintainer's
    home address, logged on the workstation (which exit is left open below).
- **Never reachable:** the home network, the workstation's own services, the lab phones, the project's server and
  the maintainer's accounts.
- **Limits, said plainly:**
  - a proxy that does not inspect TLS allows by the name the client claims, so code inside could try domain fronting
    to reach another host (Anthropic's guide says so); only `agent` can reach the proxy, and samples never run as
    `agent`;
  - whatever the agent sends to the model API leaves the machine by design: sample data the agent reads goes to the
    model, which is the point of the work and stays inside the program's terms;
  - UDP to port 443 is dropped in the sinkhole mode, so apps fall back to TCP, where the catch-all records them. An
    app that pins its certificates refuses the catch-all's, but the name it asked for and the attempt are still
    recorded, which is what Watch needs to know.

### 5. One way for data

- **In:** samples enter the machine through an inbox that the machine reads and cannot write. A brief names each
  sample by SHA-256 and source; samples never enter git.
- **Out:** only text leaves: findings, hashes, the hosts an app contacted, logs reduced to text. It leaves through an
  outbox that the workstation reads as text and never runs. Nothing executable leaves the machine.
- **One credential inside:** the verified account's Claude Code sign-in (OAuth, as the program requires; no API key,
  and no one-year token from `claude setup-token`). Anthropic's guide prefers a key injected from outside the
  sandbox; a claude.ai sign-in has no such form, so the sign-in stays with the agent's own user in the machine, the
  samples are handled by another user and run inside the nested emulator, the machine can reach only Anthropic's
  hosts, and the session signs out at the end of each job.
- **Nothing else:** no SSH key, no git credential, no signing key, no browser profile of the maintainer's. The
  machine cannot push; results reach the repositories through a lane-1 session that reads the outbox.

### 6. A test before the first live run

When the machine is built, and again whenever its image, its network rules or the model change:
- **Static:** an agent reads the machine's configuration (the VM definition, the firewall rules, the proxy's
  allow-list, the shared folders) and reports any path out.
- **Escape:** with the network closed and the maintainer watching, an agent inside is asked to reach the host, the home
  network or the internet, and to stop and report if it succeeds. Any success blocks lane 2 until it is fixed and the
  test passes again.
- **Before each job:** the tools the brief needs are checked as present, so nothing is fetched mid-run.

### 7. Records, kept outside the machine

- **Egress log:** every connection the machine attempts, allowed or denied, is logged on the host side (the firewall
  and the proxy), where the machine cannot erase it; kept at least 90 days, in persistent storage with its retention
  set explicitly (journald keeps no fixed period by default and drops messages under a flood, so the firewall's log
  goes to a file of its own).
- **Transcripts:** the agent's transcripts are copied out with the job's results and kept at least 90 days (the
  workstation's own Claude Code keeps transcripts 3650 days).
- **Review:** after each job, runs with any denied or unexpected egress are read before the results are used; any
  attempt to leave the scope is reported to Anthropic as the program asks, and recorded with the job.

### 8. Scope, supervision, halting

- **Scope:** every brief states its scope as intent: which samples, what may be done to them, which network mode
  (decision 4), and that no other host is contacted on purpose. The machine's own agent settings repeat the lane-2
  rules, with auto mode on and bypass mode off.
- **Supervision:** dynamic runs happen with the maintainer present and able to halt them; static analysis with the
  network closed may run unattended.
- **Halting:** one command on the workstation stops the machine at once; the next job starts from the clean snapshot.

### 9. Lane 1, hardened now

- **Done on 2026-11-15:** bypass mode is switched off for this project in its local settings, which are not in git
  (`permissions.disableBypassPermissionsMode`, which Claude Code honours from any settings file). The desktop app
  already starts this project's sessions in auto mode.
- **The maintainer's call,** because Claude Code takes them only from the user's own settings, which cover every
  project on the machine:
  - auto as the default mode for sessions started in a terminal (`permissions.defaultMode`; Claude Code ignores
    `auto` and `bypassPermissions` there when a project's own files set them);
  - a Datapavan section in `autoMode.environment`, stating the project, its two repositories, the lab devices in and
    out of scope, the network scope, lane 2 and the program's limits (drafted in the maintainer's private notes).
- The session's first draft of this ADR put both into the project's local settings; the documentation shows that
  Claude Code ignores them there, and they were taken out the same day.

### Against the field

- **Anthropic's guide is the bar.** Met: a VM; egress closed except the model API through a proxy on the host; tools
  installed before each job; the escape test; records kept 90 days, above the guide's 30; scope as intent; auto mode;
  halting at once. Not met:
  - the sign-in injected from outside the machine: a claude.ai sign-in has no such form (decision 5 names the risk);
  - continuous automated monitoring of transcripts: each job is reviewed after it instead, and the guide's
    sandbox-escape classifier is not yet read;
  - Firecracker: it cannot carry a nested emulator, and Anthropic's deployment guide rates QEMU the same.
- **Malware-analysis practice:** analysis VMs on a host-only network with simulated services (INetSim, FakeNet-NG)
  are the field's long-standing standard; for Android, dynamic analysis runs the app in an emulator behind a sinkhole
  or an intercepting proxy. This ADR follows that standard; it does not try to defeat certificate pinning by default.
- **The step above the field:** an AI agent that enforces the lane rule itself (it stops outside the machine and says
  why), an egress log the machine cannot touch, an escape test before every change of image, network or model, and
  the build scripts published so others can check and rerun them. No frontier research is needed; it is engineering.

## Consequences

- Lane-2 work waits until the machine exists and passes decision 6's test; all the open lane-1 work (gate 2's units,
  Watch's fixes, the editions) goes on meanwhile.
- The machine costs disk and memory on the workstation while it runs, within the machine rule for emulators.
- Building it needs downloads (a guest image, the analysis tools), each with the maintainer's word.

## Where it lands

- `lab/analysis-machine/`: the scripts that build the machine, its firewall rules and its proxy's allow-list, public
  like the rest of the lab, so others can check and reuse them.
- The maintainer's private notes: the briefs, the results, the samples' list and the account's details.

## What this does not decide

- **The exit** for a run that needs real traffic: which provider, and how it is paid for. It is never the
  maintainer's home address.
- **A dedicated lab phone** on an isolated network, for apps that refuse to run in an emulator: lab spending, the
  maintainer's call.
- **Anthropic's sandbox-escape classifier** and its "getting started" article, which the guide points to for
  reviewing transcripts: not yet read; adopting it is a later change to decision 7.
- **The maintainer's own settings** (decision 9).
- **A gateway that keeps the sign-in out of the machine,** as Anthropic's guide prefers: whether a claude.ai sign-in
  can work that way, within the program's rules, is not known.
- **The build itself:** a unit of its own, after this ADR is accepted, with each download asked for by name, source
  and size.
- **What happens to a finding:** ADR 0048's routes and the project's disclosure rule apply unchanged; lane 2 changes
  where the work runs, not how findings are handled.

## Sources

- Anthropic, "Agent containment best practices for CVP participants", 2026-10-06:
  https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants
- Anthropic, "Securely deploying AI agents" (isolation technologies; vsock and a host proxy; the limits of a proxy
  that does not inspect TLS): https://code.claude.com/docs/en/agent-sdk/secure-deployment
- Claude Code, network access requirements and proxy configuration: https://code.claude.com/docs/en/network-config
- Claude Code, settings precedence (`defaultMode` values from project files):
  https://code.claude.com/docs/en/settings; auto mode's configuration scopes:
  https://code.claude.com/docs/en/auto-mode-config
- Android, "Configure hardware acceleration for the Android Emulator" (no VM-accelerated emulator inside another VM;
  `-accel on`): https://developer.android.com/studio/run/emulator-acceleration
- Google, Android emulator container scripts (nested use, reduced performance):
  https://github.com/google/android-emulator-container-scripts
- Firecracker, nested virtualization not supported: https://github.com/firecracker-microvm/firecracker/issues/751
- Cloud Hypervisor, `--cpus nested=on`: https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/cpu.md
- Linux kernel, running nested guests with KVM (saving an L1 guest that runs an L2 guest on AMD):
  https://www.kernel.org/doc/html/latest/virt/kvm/x86/running-nested-guests.html
- Debian security tracker: https://security-tracker.debian.org/tracker/CVE-2026-53359 and
  https://security-tracker.debian.org/tracker/CVE-2026-64561
- journald.conf (`MaxRetentionSec`, rate limits): https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html
- INetSim: https://www.inetsim.org/features.html; FakeNet-NG: https://github.com/mandiant/flare-fakenet-ng
