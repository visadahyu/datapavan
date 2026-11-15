# 0051. Two lanes of work, and an isolated machine for suspect apps

- Status: Proposed
- Date: 2026-11-15
- Decided by: the maintainer, 2026-11-15, that normal work goes on as before and that sensitive security work runs
  only in an isolated machine, on a separate account verified for defensive security work, with the AI agent itself
  saying so when it reaches such work; the decisions below are proposed, drafted with AI help and revised after an
  independent review.
- Builds on: ADR [0048](0048-lab-probe-of-android-gaps.md) (decision 4, the routes for a finding) and
  [LAB.md](../LAB.md).
- Follows: Anthropic's "Agent containment best practices for CVP participants" (2026-10-06).

## Context

Datapavan is built with AI agents (Claude Code) on the maintainer's own workstation. That machine also holds other
projects and their containers, SSH and commit-signing keys, browser profiles and a mail store, and its emulators and
the lab phones share the home network. For the work so far, the project's own code, builds and tests, that is
acceptable: the desktop app starts this project's sessions in auto mode, where every agent action is reviewed before
it runs. Sessions started in a terminal follow the maintainer's own default mode, which today skips that review
(decision 11).

Work that is coming is of another kind. Watch and the audit need to know what fake or repackaged VPN and proxy apps,
apps from owners nobody can identify, and tracker SDKs actually do (DESIGN.md, and the maintainer's private incident
register), and reported flaws in messengers and circumvention tools need triage. That means handling and running
hostile code, and asking an agent to analyse it, sometimes with the model provider's default cyber safeguards relaxed
for a verified account. Three risks follow: hostile code on the workstation or its network; an agent acting beyond
the intended scope; and text from a hostile sample steering an agent that holds the maintainer's keys.

Anthropic's guide for such work asks for:
- **Isolation:** a virtual machine or a dedicated host, with egress blocked except the model API, reached through a
  proxy, with the credential injected from outside the sandbox; every tool installed before a run.
- **A test before live runs:** with a new sandbox or model, the model probes the sandbox and tries to escape it, under
  close human supervision and without internet, and stops and reports if it succeeds; tasks that may be impossible
  get extra supervision.
- **Records and monitoring:** transcripts and the sandbox's egress log kept at least 30 days; runs with denied or
  unexpected egress reviewed; automated scanning of transcripts, with a sandbox-escape classifier to choose which to
  read; out-of-scope behaviour reported to Anthropic.
- **Scope as intent:** "do not contact hosts outside X" rather than "you cannot reach the internet", so the instruction
  holds when the environment is misconfigured.
- **Auto mode,** with the environment and targets described in `autoMode.environment` rather than the mode switched
  off; and a person able to halt a run at once.

## Decision

### 1. Two lanes

- **Lane 1, normal work,** goes on as before, on the workstation, with any of the maintainer's accounts: the
  project's own code, builds and tests; emulator runs with the project's own apps and fixtures (gaps-probe included);
  documents, ADRs, research from public sources; static reading of open-source code.
- **Lane 2, sensitive work,** runs only inside the analysis machine (decision 3):
  - obtaining, installing, running or decompiling apps the project did not build that are suspected of being hostile
    (fake or repackaged VPN and proxy apps, tracker SDK samples);
  - reproducing or testing a reported flaw;
  - dynamic analysis of a suspect app with its real traffic;
  - anything that needs the verified account's relaxed safeguards, or that the default safeguards stop.
- **An exception** needs the maintainer's word for that case, recorded with it. The studies already agreed on the
  maintainer's lab phone, of apps installed on it before, stay as they were agreed.

### 2. The machine is the check, and the agent says when it gets there

An agent cannot verify from inside a session which account it runs on. What it can verify is where it runs.
- **The marker check:** the analysis machine carries a root-owned file, `/etc/datapavan-lane-2`, and a host name of
  the same meaning. A lane-2 session starts only after a check script finds both and also finds what must not be
  there: the session's user is `agent`; there is no `~/.ssh`, no git credential and no route out except the gateway
  (decision 4).
- **Outside the machine,** a session that reaches a lane-2 step stops that step, tells the maintainer in one line that
  the step is lane 2 and what it needs (the verified account, the machine ready, the scope written), writes a brief
  in the maintainer's private notes, and goes on with lane-1 work.
- **Where the rule lives:**
  - in the agents' standing notes for this project, which sessions in its folders load whatever the account (they
    are context, not enforced configuration, and subagents keep memory of their own);
  - proposed, for the maintainer's word: a `CLAUDE.md` in this repository and in the private notes' repository with
    the lane rule, which every session and subagent loads and which the auto-mode classifier also reads (still
    context, not enforcement); and a guard hook, which Claude Code's documentation names as the way to block an
    action whatever the agent decides, that refuses, outside the machine, `adb install` of any file that is not one
    of the project's own build outputs and any read of the sample inbox;
  - in the maintainer's own settings, which are the maintainer's call (decision 11).

### 3. The analysis machine

- **A QEMU/KVM virtual machine (libvirt) on the workstation.** Dynamic analysis needs the Android Emulator inside the
  machine, and the emulator needs KVM there: nested virtualization. No supported or documented way to run a
  KVM-accelerated Android Emulator inside a Firecracker guest was found, so Firecracker, which Anthropic's CVP guide
  names for Linux, is not used. Cloud Hypervisor documents nested virtualization (`--cpus nested=on`) but no report of
  the Android Emulator on it was found; it is the fallback. Anthropic's deployment guide lists QEMU beside Firecracker
  as a VM with excellent isolation when set up correctly, and adds that a VM's security depends heavily on the
  hypervisor and its device emulation, which is why decision 3 removes every device the work does not need.
- **Nested virtualization is the sharp edge:**
  - Android's documentation says a VM-accelerated emulator cannot run inside another VM; Google's own container
    scripts run it nested, more slowly. So the build starts with a pilot: the emulator must boot inside the machine
    with `-accel on` (which fails rather than falling back to slow emulation) and `/dev/kvm` present.
  - KVM's shadow paging, which nested guests use, has had serious flaws: CVE-2026-53359 and CVE-2026-64561, both
    fixed in Debian's 7.2.15-1 kernel, the one the workstation runs. The workstation follows Debian's security
    updates; lane 2 pauses while a fix for a KVM flaw is published and not yet installed. The SVM extension is
    offered to this machine only.
  - **If the pilot fails:** the fallback is the emulator on the workstation under a user of its own, in a network
    namespace whose only link is the sinkhole, driven from the machine over a forwarded adb port. That has no VM
    boundary around the emulator, so it needs the maintainer's word before it is used.
- **Devices:** a serial console and no graphics, or VNC without a clipboard; no SPICE channels, no USB redirection,
  no shared clipboard or drag and drop, no QEMU guest agent, no shared folders. The maintainer types the sign-in code
  on the console.
- **Inside the machine:**
  - **Two users:** `agent` runs Claude Code with the verified account's sign-in; `samples` owns the samples, the
    emulator and the tools that open them. `agent` hands work to `samples` only through fixed wrapper scripts that a
    sudo rule names one by one, and reads back only their output files.
  - **Tools:** installed from a pinned list, with hashes, when the image is built (jadx, apktool, androguard, the
    emulator and its system images); nothing is fetched during a job.
  - **Claude Code's own settings:** auto mode, bypass mode off, WebFetch and WebSearch denied, claude.ai connectors
    off (`disableClaudeAiConnectors`), artifacts off (`enableArtifact: false`), Remote Control off, and
    `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` set. The verified account keeps no connectors and no personal content.
- **Size:** it takes the place of two emulators under the workstation's machine rule (up to 8 threads and 12 GB),
  and runs alone when a timing result depends on it.

### 4. Network: closed by default, decided on the host

The machine's design must hold even if code inside it gains root. So every rule that matters is on the workstation,
where the machine cannot change it.

- **Host side:**
  - an isolated libvirt network with no forwarding, no DNS and no DHCP from libvirt (static addresses), so the guest
    has no resolver to tunnel through;
  - two network interfaces: the agent's, which reaches only the model gateway, and the samples', which reaches only
    the sinkhole; both run on the workstation, outside the machine;
  - an nftables `inet` table that drops everything else from the machine's bridge, including toward Docker's published
    ports (a rule in Docker's `DOCKER-USER` chain as well, since Docker forwards them past an input-only rule); IPv6
    off on the bridge;
  - the ruleset's hash checked before each job, since libvirt and Docker rewrite rules when they reload.
- **The model gateway** terminates TLS for the machine (whose image trusts the gateway's own certificate authority),
  passes only the API paths and sign-in hosts Claude Code needs with a claude.ai sign-in (`api.anthropic.com`;
  `claude.ai`, `claude.com` and `platform.claude.com`), refuses every other path (file uploads, batches and the
  rest), and logs each request's path and size. Without it, a guest that gains root could send data to someone else's
  account on Anthropic's own allowed host, which a proxy that only reads the host name cannot see. Whether it can also
  refuse any credential but the one this machine signed in with is designed in the build unit.
- **The suspect app's traffic,** in the mode the brief names:
  - **none:** static work; the app never runs, or runs with no network at all;
  - **sinkhole,** the default for dynamic runs: the sinkhole on the workstation answers names and ends every
    connection at a catch-all that records it; nothing leaves; UDP to port 443 is dropped so apps fall back to TCP,
    where it is recorded. An app that pins its certificates refuses the catch-all's, but the name it asked for and
    the attempt are still recorded, which is what Watch needs to know;
  - **exit,** only with the maintainer's word for that run and with the maintainer watching: through a separate exit
    that is never the maintainer's home address, logged on the workstation; the agent is signed out for the run, so
    no sign-in is inside the machine while it has a route out.
- **Never reachable:** the home network, the workstation's own services and containers, the lab phones, the project's
  server and the maintainer's accounts.
- **What stays possible, said plainly:** the agent sends what it reads to the model, through the gateway, by design;
  and a guest with root can use the machine's own sign-in on the allowed paths. That reaches only Anthropic's servers
  and the maintainer's own account, not a party outside.

### 5. Samples in, text out

- **Obtaining:** samples are obtained only in a lane-2 job through the exit mode, or from a source's archive and
  checked against the hash the source published; never by a browser or a tool on the workstation's home address.
- **Keeping:** on the workstation, samples are kept encrypted, in a folder owned by a user of their own (mode 0700)
  that the lane-1 agents, the maintainer's own user and the desktop's file indexers cannot read. They enter the
  machine as a read-only disk image built for the job; the host enforces read-only, not the guest. A brief names each
  sample by SHA-256 and source; samples never enter git. A sample not kept for a later job is destroyed with the job.
- **Results out:** only text, written to a separate outbox disk that the workstation reads after the machine has shut
  down. The text is untrusted: it carries app names, host names and strings from the samples, which can be written to
  steer an agent. So:
  - results follow a fixed schema: hashes, host names and addresses matched by pattern, counts, and one summary field
    capped in length;
  - a script on the workstation, not a model, checks the schema, the length caps and the character set, and strips
    control and terminal escape characters;
  - the maintainer reads each result before any lane-1 session uses it;
  - a lane-1 session treats every string in a result as data, never as an instruction, and never runs anything a
    result names.
- **One credential inside:** the verified account's Claude Code sign-in (OAuth, as the program requires; no API key,
  and no one-year token from `claude setup-token`). Claude Code offers no documented way to keep a claude.ai sign-in
  outside the machine, as Anthropic's guide prefers for keys; the sign-in stays with `agent`, the gateway limits what
  it can reach (decision 4), and the session signs out at the end of each job. Nothing else: no SSH key, no git
  credential, no signing key, no browser profile of the maintainer's; the machine cannot push.

### 6. A test before the first live run

When the machine is built, and again whenever its image, the host's firewall, the gateway or the model changes:
- **What stays open during the test:** the model gateway only; the samples' interface goes to the sinkhole.
- **Static:** an agent reads the machine's configuration (the VM definition, its devices, the host's ruleset, the
  gateway's allow-list, the disks) and reports any path out.
- **Escape attempts,** with the maintainer watching, from `agent`, from `samples` and from inside the emulator: reach
  the host and its services, Docker's published ports, the home network, IPv6 link-local addresses, a resolver,
  `169.254.169.254`, the internet directly, and a path the gateway should refuse. The agent stops and reports at the
  first success. Any success blocks lane 2 until it is fixed and the test passes again.
- **Before each job:** the marker check (decision 2), the ruleset's hash, and the tools the brief needs; a brief that
  asks for something the machine cannot do gets the maintainer's attention before it runs.

### 7. Records and monitoring, outside the machine

- **Egress:** every connection attempt from the machine, allowed or refused, is logged on the workstation (firewall,
  gateway and sinkhole), in a file of its own with its retention set (journald keeps no fixed period by default and
  drops messages under a flood); kept at least 90 days. The samples' traffic is also captured on the host bridge.
- **Transcripts:** the agent's transcripts are copied out with the job's results and kept at least 90 days.
- **Review:** every transcript is scanned after its job, not only runs with refused traffic; before the first live
  run, Anthropic's sandbox-escape classifier and its "getting started" guide are read and, where they fit, adopted.
  Any attempt to leave the scope is reported to Anthropic as the program asks, and recorded with the job.
- **Supervision:** until a monitor on the workstation exists that knows each job's scope and can stop the machine by
  itself, every lane-2 run happens with the maintainer present.

### 8. Scope and halting

- **Scope:** every brief states its scope as intent: which samples, what may be done to them, which network mode
  (decision 4), and that no other host is contacted on purpose. The machine's agent settings repeat the lane-2 rules.
- **Halting:** one command on the workstation destroys the running machine at once.

### 9. Clean for each job

After a job the machine is destroyed, its disk overlay deleted and its UEFI variables reset from the template (or it
boots without UEFI); it has no TPM. Its state is never saved and no snapshot with memory is ever taken or restored (on
AMD, a saved guest that was running its own guest can no longer be trusted). The base image is read-only and its hash
is checked before each job.

### 10. If something gets out

If any test, log or transcript suggests that code or the agent reached beyond the machine: stop lane 2, destroy the
machine and keep its disks and the logs as they are; check the workstation; replace the keys it holds (SSH, commit
signing, the accounts' sessions) and reinstall it if the check cannot rule out a compromise; report to Anthropic
within the program's time limits (24 hours for a security incident); record what happened in the private notes and
publish what users of the lab scripts need to know.

### 11. Lane 1, hardened now

- **Done on 2026-11-15:** bypass mode is switched off for this project in its local settings, which are not in git
  (`permissions.disableBypassPermissionsMode`, which Claude Code honours from any settings file).
- **The maintainer's call,** because Claude Code reads them only from the user's own or managed settings, the
  `--settings` flag or an SDK caller, never from a project's own settings files (so that a repository cannot widen
  its own permissions):
  - auto as the default mode for sessions started in a terminal (`permissions.defaultMode`), in every Claude Code
    configuration folder on the workstation;
  - a Datapavan section in `autoMode.environment`, stating the project, its two repositories, the lab devices in and
    out of scope, the network scope, lane 2 and the program's limits (drafted in the maintainer's private notes).
- The first draft of this ADR put both into the project's local settings; Claude Code ignores them there, and they
  were taken out the same day.

### Against the field

- **Anthropic's CVP guide is the bar.** Met: a VM; egress closed except the model API through a gateway on the host;
  tools installed before each job; the escape test, from every user and from inside the emulator; records kept 90
  days, above the guide's 30; scope as intent; auto mode; halting at once; supervision of every run. Not met, or not
  yet:
  - the credential injected from outside: a claude.ai sign-in has no documented form for it (decision 5);
  - continuous automated monitoring: every transcript is scanned after its job, and every run is supervised until a
    host monitor exists;
  - the hypervisor: the CVP guide names Firecracker for Linux; it cannot carry a nested emulator, so this ADR uses
    QEMU/KVM, which Anthropic's deployment guide rates as excellent isolation when set up correctly, with every
    device it does not need removed.
- **Malware-analysis practice:** analysis VMs on an isolated network with simulated services (INetSim, FakeNet-NG)
  are the field's long-standing standard; for Android, dynamic analysis runs the app in an emulator behind a sinkhole
  or an intercepting proxy. This ADR follows that standard; it does not try to defeat certificate pinning by default.
- **The step above the field:** treating text from the samples as hostile on its way back to an agent with keys
  (decision 5), a model gateway that limits the allowed host to the paths the agent needs (decision 4), and the
  build scripts published so others can check and rerun them. No frontier research is needed; it is engineering.

## Consequences

- Lane-2 work waits until the machine exists and passes decision 6's test; all the open lane-1 work (gate 2's units,
  Watch's fixes, the editions) goes on meanwhile.
- Every lane-2 run needs the maintainer present until a host monitor exists, which limits how much lane 2 can do.
- The machine costs disk and memory on the workstation while it runs, within the machine rule for emulators.
- Building it needs downloads (a guest image, the analysis tools, the sinkhole), each with the maintainer's word.

## Where it lands

- `lab/analysis-machine/`: the scripts that build the machine, the host's ruleset, the gateway's allow-list, the
  results schema and its checker, and the marker check, public like the rest of the lab, so others can check and
  reuse them.
- The maintainer's private notes: the briefs, the results, the samples' list and the account's details.

## What this does not decide

- **The exit** for a run that needs real traffic: which provider, and how it is paid for. It is never the
  maintainer's home address.
- **A dedicated lab phone** on an isolated network, for apps that refuse to run in an emulator: lab spending, the
  maintainer's call. Its radios would leave the host's firewall behind, so it needs its own ADR.
- **The gateway's build:** whether it can tie requests to the machine's own sign-in, and whether a gateway that holds
  the sign-in itself is possible within the program's rules.
- **Personal data in captures:** in sinkhole mode a sample sees no one's real data; in exit mode it may fetch others'.
  Captures stay inside the job; results carry no personal data; what may be published about a capture follows the
  project's disclosure rule.
- **The maintainer's own settings,** the proposed `CLAUDE.md` files and the guard hook (decisions 2 and 11).
- **The build itself:** a unit of its own, after this ADR is accepted, with each download asked for by name, source
  and size.
- **What happens to a finding:** ADR 0048's routes and the project's disclosure rule apply unchanged; lane 2 changes
  where the work runs, not how findings are handled.

## Sources

- Anthropic, "Agent containment best practices for CVP participants", 2026-10-06:
  https://support.claude.com/en/articles/17317514-agent-containment-best-practices-for-cvp-participants
- Anthropic, "Securely deploying AI agents" (isolation technologies and their caveats; vsock and a host proxy; the
  limits of a proxy that does not inspect TLS): https://code.claude.com/docs/en/agent-sdk/secure-deployment
- Claude Code, network access requirements and proxy configuration: https://code.claude.com/docs/en/network-config
- Claude Code, settings and their scopes: https://code.claude.com/docs/en/settings; auto mode's configuration
  scopes: https://code.claude.com/docs/en/auto-mode-config; memory: https://code.claude.com/docs/en/memory
- Android, "Configure hardware acceleration for the Android Emulator" (no VM-accelerated emulator inside another VM):
  https://developer.android.com/studio/run/emulator-acceleration; the emulator's command line (`-accel on`):
  https://developer.android.com/studio/run/emulator-commandline
- Google, Android emulator container scripts (nested use, reduced performance):
  https://github.com/google/android-emulator-container-scripts
- Cloud Hypervisor, `--cpus nested=on`: https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/cpu.md
- Linux kernel, running nested guests with KVM (saving an L1 guest that runs an L2 guest on AMD):
  https://www.kernel.org/doc/html/latest/virt/kvm/x86/running-nested-guests.html
- Debian security tracker: https://security-tracker.debian.org/tracker/CVE-2026-53359 and
  https://security-tracker.debian.org/tracker/CVE-2026-64561
- libvirt, isolated networks: https://libvirt.org/formatnetwork.html; Docker and nftables or iptables
  (`DOCKER-USER`): https://docs.docker.com/engine/network/packet-filtering-firewalls/
- journald.conf (`MaxRetentionSec`, rate limits): https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html
- INetSim: https://www.inetsim.org/features.html; FakeNet-NG: https://github.com/mandiant/flare-fakenet-ng
