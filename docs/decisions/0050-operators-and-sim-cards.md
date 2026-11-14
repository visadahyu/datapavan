# 0050. Mobile operators and SIM cards: what the phone installed, what the SIM can do, what to tell users

- Status: Proposed
- Date: 2026-11-14
- Decided by: the maintainer, 2026-11-14, that the risks of mobile operators and SIM cards become part of the plan;
  the decisions below are proposed, drafted with AI help.
- Builds on: ADRs [0015](0015-dataset-licences.md) (decision 10), [0016](0016-no-user-data.md),
  [0023](0023-maker-software-and-system-keys.md), [0025](0025-guided-check-and-traffic-facts.md),
  [0026](0026-remediation-plan-v0.1.md), [0030](0030-more-languages-reviewed-by-independent-models.md),
  [0045](0045-three-editions-of-one-app.md), [0046](0046-live-activity.md) and
  [0048](0048-lab-probe-of-android-gaps.md).
- Amends, once accepted: the audit's finding "Not from a known app store" (`UNKNOWN_SOURCE`), which stops covering
  installs made by the phone's own software (decision 1).

## Context

Two parties besides the phone's maker run software on every phone with a SIM: the mobile operator, through the SIM
and through apps the SIM switches on, and the partners that makers and operators let install apps. Datapavan has
looked at the maker's software (ADR 0023) but not at these. Their risks are documented, and some of them sit where
no app without system privileges can see.

Tags: **[standard]** an ETSI or 3GPP specification; **[code]** AOSP source, read but not tested on a device;
**[doc]** Android's documentation; **[report]** a researcher's, vendor's or authority's own publication;
**[unverified]** not checked. Makers ship their own telephony and SIM Toolkit builds, so AOSP's behaviour is a
baseline, not a statement about any maker's phone.

**The SIM is a small computer the phone obeys.**
- **Proactive commands.** The SIM's applets send the phone commands (ETSI TS 102 223, the Card Application
  Toolkit) **[standard]**. With a null alpha identifier, SEND SHORT MESSAGE tells the phone to give the user no
  information that it is sending. PROVIDE LOCAL INFORMATION returns the location, the IMEI and more, with no user
  step. SET UP CALL has a confirmation phase.
- **What AOSP does with them** **[code]**:
  - SEND SHORT MESSAGE, SEND SS and SEND USSD show at most a toast of the SIM's text, and nothing when the SIM gives
    none (`StkAppService`). SEND SS can switch on call forwarding.
  - Location and IMEI requests are answered by the modem; Android's `CatService` answers only the date, time and
    language itself and passes nothing to any app.
  - OPEN CHANNEL, a data channel the SIM opens through the phone, is accepted without a prompt when the SIM gives no
    text, since `config_stkNoAlphaUsrCnf` defaults to true.
  - LAUNCH BROWSER with no text opens the browser without asking, after setup and unless the operator's carrier
    configuration turns it off. The silent path is in AOSP from Android 7.0 to `main`, so on every version
    Datapavan supports.
  - SET UP CALL always asks.
- **The operator changes the SIM's applets over the air.** ETSI TS 102 225 and 102 226 define secured packets and
  remote management of files and applets **[standard]**. Each applet has a minimum security level, set when it is
  installed; an applet whose level asks for no checksum or ciphering accepts commands from anyone who can send it an
  SMS.
- **Messages the user never sees.** A "type 0" short message is acknowledged and discarded, and the phone "shall not
  indicate" it to the user (3GPP TS 23.040, clause 9.2.3.9) **[standard]**; AOSP logs it and stops
  (`GsmInboundSmsHandler`) **[code]**. SIM data-download messages go to the SIM, not to an app.

**Documented abuses.**
- **Simjacker (2019).** AdaptiveMobile Security found the S@T Browser applet abused to make SIMs report their cell
  and IMEI by SMS, with nothing shown on the handset, whatever its system **[report]**. The researchers attribute it
  to a surveillance company working for governments, which they do not name. The attack was aimed mostly at
  subscribers from Mexico, also from Colombia and Peru; in one 31-day period more than 25,000 attack messages went
  to more than 1,500 subscribers. The applet was in use by 61 operators in 29 countries. Its FAQ says that there is
  very little a person can do.
- **WIBattack (2019).** Ginno Security Lab described the same class of flaw in the WIB applet, with no exploitation
  claimed, and reported it to the GSMA **[report]**. Its claim that every command runs silently does not hold for
  SET UP CALL on AOSP, which asks.
- **How many SIMs.** SRLabs measured about 800 SIMs: 9.1 % were vulnerable to one of the two **[report]**. Its tool
  that detects such messages, SnoopSnitch, needs a rooted phone with a Qualcomm chipset.
- **Silent messages used by states.** The German government's answers to the Bundestag give tens of thousands of
  "stille SMS" sent by two federal police authorities in 2022 **[report]**; the documents do not say which
  technical form these take.

**SMS login codes fail on the operator's side.**
- **SIM swaps.** The FBI counted 1,611 SIM-swap complaints with losses above $68 million in 2021 alone, through
  social engineering of carriers, bribed insiders and attacks on carrier staff **[report]**. The SEC said its X
  account was taken in 2024 after someone obtained control of its phone number "via the telecom carrier"
  **[report]**. A Princeton study found that five US prepaid carriers used challenges an attacker could subvert, and
  that 17 of more than 140 websites let an account be taken over by a SIM swap alone (SOUPS 2020) **[report]**.
- **Rules.** The FCC's 2023 order makes US carriers authenticate SIM changes and port-outs, notify customers and
  offer free account locks **[report]**. NIST SP 800-63B-4 restricts the phone network for out-of-band verification
  and counts a SIM change or port as a risk indicator **[report]**.
- **Codes taken through the operator.** Guarnieri and Anderson (Black Hat USA 2016) write that an attacker can
  convince or compel a provider to issue a copy of a SIM and so receive a messenger's login code, and that, by
  accounts from inside Iran, these tactics "appear to have been used" there; they say the same tactics are
  documented in other countries **[report]**.

**Apps the operator or the maker switch on or install.**
- **Carrier privileges.** Rules on the SIM give an app carrier privileges by its signing certificate, and an app from
  an ordinary store can hold them (source.android.com, UICC carrier privileges) **[doc]**. A privileged app reads the
  IMEI, IMSI and phone number, sends raw commands to the SIM, sends SMS without storing them, and changes network
  settings. The operator controls the rules and can change them over the air.
- **Carrier apps a SIM enables.** Preinstalled apps on the maker's list stay hidden until a SIM gives them carrier
  privileges; Android then installs them for the user and grants them the phone, background-location and SMS
  permissions without a prompt (`CarrierAppUtils`, `DefaultPermissionGrantPolicy`) **[code]**.
- **Installs in the background.** AOSP's Settings text says: "Your device manufacturer may install apps on your
  device in the background, or allow your carrier and other partners to do so." Android 14's
  `BackgroundInstallControlService` counts such installs, but only system apps may read its list **[code]**. A
  vendor of this service, Digital Turbine, describes "Dynamic Installs" at activation and setup "with or without the
  device user's interaction" **[report]**.
- **The SIM Toolkit's icon comes from the SIM.** `com.android.stk`'s launcher entry is disabled until the SIM sends
  a menu; Android then enables it under the menu's title, often the operator's brand, and disables it when no SIM
  has one **[code]**.

**What an app without system privileges can see,** with `QUERY_ALL_PACKAGES`, as Basic holds:
- **Yes:** every app's installer of record and, from Android 11, the package that actually ran the install
  (`InstallSourceInfo.getInitiatingPackageName`), which a later installer cannot rewrite **[doc]**, and the
  initiating package's signing certificates; each app's first install time; whether an installer holds
  `INSTALL_PACKAGES`; whether `com.android.stk`'s launcher entry is enabled, and probably the label the SIM gave it
  **[unverified]**; the default SIM's operator name, MCC and MNC, country and carrier name, with no permission; and
  whether the app itself has carrier privileges.
- **No:** which apps hold carrier privileges (`getPackagesWithCarrierPrivileges` is a system API); the SIM's applets
  (OMAPI refuses an applet the SIM's rules do not grant to the caller); incoming over-the-air, binary or type-0 SMS;
  proactive commands; the list of background installs; and, without `READ_PHONE_STATE`, the second SIM of a
  dual-SIM phone.

**What Basic reports today** (`main` and 0.1.2 alike). The audit reads only the installer of record
(`audit/Collectors.kt`). A user app whose installer is not in `audit/Stores.kt` gets the information finding "Not
from a known app store" (`audit/Rules.kt`), whose text says: "That is fine if you installed it yourself from its
official website; a modified copy can carry spyware." For an app installed by a maker's or operator's agent this is
wrong, since the user did not install it, and alarming, since it hints at spyware where the source is the phone's
own software. The app's page says "Installed by" with the agent's label and package, which is right. A carrier app
that a SIM switched on is a system app and reads "Preinstalled system app", with nothing about the SIM or the
permissions Android gave it.

## Decision

### 1. Basic shows what the phone's own software installed

- **The facts read, with no new permission:** the installer of record and, on Android 11 and later, the initiating
  installer and its signing certificate; whether that installer is a system app, whether it holds
  `INSTALL_PACKAGES` (`PackageManager.checkPermission`) and whether it is signed with this phone's system key
  (ADR 0023); the package source on Android 13 and later; and the first install time.
- **The rule.** A user app counts as installed by the phone's own software when its initiating installer, or its
  installer of record where Android gives no initiating one, is a system app that holds `INSTALL_PACKAGES` and is
  neither a store in `audit/Stores.kt` nor the phone's package installer (found on the phone, as the safety floor
  already finds it). The lab's first rows (decision 5) record what each field holds after an install from a store,
  through the package installer, by adb and by a maker's or operator's agent, and the rule is fixed against them
  before it ships.
- **Its own finding, at the information level,** in place of "Not from a known app store". In sense: "Installed by
  {label} ({package}), part of the phone's own software, on {date}, not through a store you used here. Phone makers
  and mobile operators install apps this way, during setup, when a SIM is inserted, or when you move to a new phone.
  It may also be a maker's store that Datapavan does not list yet." It never says "without your consent": Basic
  cannot know whether the user tapped something during setup.
- **"Not from a known app store" keeps its text** for installs by ordinary apps, such as a browser or a file
  manager, and with no installer, where it is right.
- **A filter in the app list,** "Installed by the phone's software", ordered by install time, with the installer
  and its package on each row.
- **The SIM, at the time of the audit,** on the same view: the operator's name as the SIM gives it, the carrier
  name, MCC and MNC, and country, of the default SIM. The view says plainly that Android does not record which SIM
  was in the phone when an app was installed, and that a second SIM is not shown.
- **A self-check line:** Datapavan holds no carrier privileges (`hasCarrierPrivileges`), as it should not.

### 2. Basic explains the SIM Toolkit and the carrier apps, with honest limits

- **The SIM Toolkit,** on the phone destination, when its launcher entry is enabled. In sense: "Your SIM has a menu
  named '{label}'. It is software on your SIM, run by your mobile operator. By the SIM standard, a SIM can ask the
  phone to send a text message, open a data connection or open a web page, and on many Android versions the phone
  does so without asking you. Android asks before a SIM starts a call. When a SIM asks for the phone's location or
  identity, the modem answers, not Android, and no app can see it. Your operator also knows which cell
  your phone uses whenever it is on its network. Datapavan cannot see what is on your SIM or what it does. If your
  SIM is many years old, your operator can give you a current one." The label is the SIM's and is shown
  bidi-isolated, as other apps' labels are.
- **Carrier apps,** as a section of the same page and a mark on each app's page, for system apps that Android
  holds disabled until a SIM uses them, or that declare a carrier service (`CarrierService`,
  `CarrierMessagingService`), and, as a separate fact, system apps that hold the phone, background-location and SMS
  permissions together. In sense: "Android turns on some preinstalled apps when a SIM from a given operator is
  inserted, and gives them phone, background location and SMS permissions without asking. This app has {facts}.
  Datapavan cannot list which apps your SIM gave special rights to: Android shows that only to system apps." The
  sentence is about the mechanism, which AOSP's code supports, never a claim about the app.
- **Nothing is offered for removal by default** (ADR 0023, decision 7). Carrier apps can carry calls, messages or
  Wi-Fi calling; they come under ADR 0026's preinstalled rule, at the strict level only and with its care step, and
  `com.android.stk` stays on the safety floor (`data/remediation/floor.tsv`, telephony).
- **What Basic cannot detect is said, not implied:** an attack through the SIM, such as Simjacker, a silent message,
  or a SIM swap in progress. No app can, without root and modem access.
- **This part waits for the lab's rows** of decision 5 (items 2 and 3) on the emulator and the A40: whether another
  app reads the SIM-given label, which toolkit package a maker uses, and what the disabled-until-used state looks
  like there. Where a row has not been measured, the text does not claim it.

### 3. Guidance for users: SMS codes, the SIM PIN, and what an operator can do

- **A page in Basic,** "Your number and your SIM", under the phone destination, and **the same on the website.** It
  needs no network: the website's copy is for people who have not installed Datapavan.
- **SMS codes.** A code sent by SMS proves that someone controls a phone number, not that it is you. Whoever
  controls the number receives it: the operator, anyone who gets a copy of the SIM or moves the number, which is a
  SIM swap. The page advises, in this order:
  - a passkey or a security key where a service offers one, then an authenticator app, rather than SMS;
  - each messenger's own second step, which a code alone does not pass: Telegram's two-step verification password,
    WhatsApp's two-step verification, Signal's Registration Lock. Each name links to the service's own help page,
    read and dated when the text is written;
  - removing the phone number as a way to recover an account, where the service allows it;
  - never giving anyone a code, whoever asks for it;
  - asking the operator for a lock or PIN on SIM changes and number moves, where it offers one.
- **A SIM PIN.** With it, a SIM taken from the phone cannot be used in another phone to receive codes. The page
  shows where Android sets it and warns that a few wrong tries lock the SIM until its PUK, which the operator holds.
- **For people at risk, what a SIM and an operator can and cannot do:**
  - **can:** know the phone's cell while it is on the network; read SMS and see whom the phone calls and when; give
    a copy of the SIM, or move the number, and so receive login codes; change the SIM's software over the air; and,
    through the SIM, make the phone send messages, open data connections or web pages, and report its location and
    IMEI, mostly without the user seeing it;
  - **cannot:** read end-to-end encrypted messages or the content of encrypted connections, or, in Android's own
    code, start a call through the SIM without a prompt;
  - **signs to know:** a sudden loss of signal and SMS can mean a SIM swap, which the FBI advises people to watch
    for; airplane mode stops the phone's contact with the mobile network.
- **Translated as ADR 0030 says,** in the eight languages, one model translating and two reviewing alone. These are
  care texts and get the closest reading. Each claim on the page cites the source this ADR cites for it.

### 4. Advanced marks operator and maker apps' traffic, like any app's

- **The same view as every app.** Operator and maker apps' flows show in Advanced's per-app view (ADR 0046) as any
  app's do, with a mark that says how the app came: "installed by the phone's software" (decision 1), and, once
  decision 2 ships, "carrier app". The mark is a fact, never an alert, a colour or a rank (ADR 0025).
- **A page the SIM opens** counts under the browser that opens it, as a Custom Tab does (ADR 0048, decision 3).
- **What Advanced does not see is said on the view** (ADR 0046, decision 5), once the lab measures it: a data
  channel the SIM opens goes through the modem and is not expected to reach Android's VPN **[unverified]**, nor are
  the SIM's messages.

### 5. The lab measures the mechanisms, with a lab SIM only

- **Lab SIMs only.** Every run uses a SIM bought for the lab and used for nothing else: never a personal SIM, never
  a number tied to anyone's accounts, and never the SIM of a person being helped. Programmable test SIMs, whose keys
  the lab holds, are the only cards whose applets a run may change.
- **Lab phones only, under consent for each device and each session** (ADR 0048, decision 5): the run script
  refuses a phone not named on its command line, and the lab app shows the phone's model and serial and waits for
  the maintainer to confirm, as ADR 0048's fixture does. The emulator comes first wherever it can stand in: its
  console can inject an SMS as a raw PDU **[unverified]**, and whether its simulated modem can send proactive
  commands is checked before any card is bought.
- **What it measures,** each as a row of `docs/platform-gaps/` by Android version and build:
  1. **Install sources:** `getInstallSourceInfo`'s fields and the first install time of every package, with no SIM
     and with each lab SIM, after setup with and without Wi-Fi; this fixes decision 1's rule and shows which apps a
     maker or an operator installs on insertion, and how they appear.
  2. **Carrier apps:** each system app's enabled state, the disabled-until-used state and its granted permissions,
     with no SIM and with each lab SIM.
  3. **The SIM Toolkit:** whether its launcher entry is enabled, and the label another app reads, with each lab SIM
     and with none.
  4. **Silent commands,** with a programmable SIM: which of SEND SHORT MESSAGE (and whether it appears in the sent
     messages), LAUNCH BROWSER, OPEN CHANNEL, SET UP CALL and PROVIDE LOCAL INFORMATION run without a prompt, on
     which Android versions and makers' builds.
  5. **Type 0:** whether a type-0 message reaches Android or stops at the modem, and that nothing is shown.
  6. **Advanced and the SIM:** with Advanced running, the SIM Toolkit's own menu items, and whether any of their
     traffic appears in Watch and under which app.
  7. **What is closed:** `hasCarrierPrivileges` and OMAPI's answers from a test app, with each lab SIM, recorded to
     show what an app cannot reach.
- **Stop rules.** Never send an over-the-air, binary or type-0 message to a SIM the lab does not own; never send a
  command to a commercial SIM's card manager or try its keys; never probe an operator's network. A raw output is
  checked for the lab SIM's number, ICCID and IMSI and the phone's IMEI before it is committed, and they are removed.
- **Under ADR 0048's rules:** each row with the image's or build's identity, its source, one command that
  reproduces it, the date and the replication column; a new weakness in Android goes to Google first, under 90 days;
  one in a maker's toolkit goes to the maker, and one in a SIM applet to the card's maker or the operator, as
  Simjacker's and WIBattack's researchers went through the GSMA. Rows that name a maker's or an operator's software
  follow ADR 0048, decision 6: a lab report, with the company asked for comment first.

### 6. Names

- **ADR 0015, decision 10, holds** for every maker, operator, vendor or app named, in the app, on the website, in
  the lab's rows or in data files: a primary source, or a reproduction on the lab's phones; facts, never
  accusations; disputes through `data/CORRECTIONS.md`.
- **Documented abuses are cited** by their researchers' own reports, with the countries, numbers and attribution as
  those reports state them, and no more.
- **Operators are named only where a primary source names them.** None of the sources above does, so no operator is
  named today. A lab SIM's operator is named in a row only after it has been asked for comment.
- **An installer is shown by its package and its label on the phone,** never by a company Datapavan infers from it
  (ADR 0023, decision 3).

## Against the field

- **SIM-attack detection** is SnoopSnitch's, from SRLabs: it needs root and a Qualcomm modem. SIMtester, also from
  SRLabs, tests a card through a reader. Nothing in this ADR detects such attacks, and no app without system
  privileges can; that is said in the app instead of being implied.
- **What an ordinary user can check:** AOSP's own Settings page, "Apps installed in the background", is the
  platform's answer where a maker shows it; whether a given phone shows it is not known. Tools that list apps show
  the installer Android records; whether any shows the initiating installer was not checked. No consumer tool was
  found that shows the initiating installer, the apps a SIM switched on and the SIM Toolkit's SIM-given name
  together, with plain limits; the field was not surveyed widely, so this is unknown rather than settled.
- **Guidance on SMS codes** follows the standard of the field (NIST SP 800-63B-4, the FBI's advice). The step above
  it is honesty about what an operator can do, said to people at risk in their own language.
- **The step above the field** is the lab method: a published, repeatable way to measure which apps makers and
  operators install or switch on, across makers' builds, that others can rerun. No frontier research is needed; it
  is lab work, and the detection of SIM attacks stays out of reach of any unprivileged app.

## Consequences

- **A correction.** An app the phone's own software installed no longer reads as a possible modified copy. Users
  see who installed it and when.
- **Users learn where the operator stands:** what its SIM and its apps can do on the phone, and why SMS codes are
  weaker than they look, with steps that work on any phone and need no Datapavan feature.
- **No new permission.** Basic keeps its permissions and never holds INTERNET; the SIM line needs none.
- **Limits stay visible:** the installer's name can be hidden once it is uninstalled; Android 10 gives the installer
  of record only; installs made through Google Play on a partner's behalf look like the user's own; a second SIM is
  not shown; and the SIM at the audit may not be the SIM at the install.
- **More texts to translate and review** in eight languages, care texts among them, and service help pages to read
  again when they change.
- **Lab costs:** at least one lab SIM, later a programmable SIM and a card reader, and sessions on lab phones under
  consent. Rows from makers' builds stay few until ADR 0048's wider set of makers is decided.
- **The rule of decision 1 depends on measurements,** so decision 1 ships only once the lab's first rows of item 1
  exist.

## Where it lands

- **Datapavan Basic 0.2.0** (with Advanced 0.2.0, from the same commit): decision 1, with its correction of "Not
  from a known app store", the filter and the SIM line; decision 3's page in the app and on the website.
- **Datapavan Advanced 0.2.0:** decision 4's mark "installed by the phone's software" in the per-app view (W5),
  since Advanced holds Basic's audit.
- **Datapavan Basic 0.2.1 and Advanced 0.2.1:** decision 2, after the lab's rows for items 2 and 3, with
  Advanced's "carrier app" mark; decision 4's line on what Advanced does not see, after item 6.
- **The lab:** item 1's rows for a store, the package installer and adb, on the emulator, before 0.2.0, and its
  rows for an agent's installs on the A40 with a lab SIM; items 2, 3, 5, 6 and 7 before 0.2.1, on the emulator and
  the A40; item 1's rows after setup when the maintainer agrees to a reset; item 4, which needs a programmable SIM,
  when one is bought.

## What this does not decide

Each of these needs the maintainer's word:
- **spending:** a lab SIM, a programmable SIM and a card reader, and a Pixel for AOSP's baseline;
- **a factory reset of a lab phone,** which item 1 needs for its "after setup" rows, since it erases the apps kept
  on the phone for other measurements;
- **outreach:** asking operators or makers for comment, reporting to the GSMA, or a report from the rows.

Also outside this ADR:
- **eSIMs:** whether an eSIM's profile carries the same toolkit and applets was not researched;
- **the network itself:** fake base stations, SS7 and the cellular identifiers a network asks for, which Android
  warns about on some phones and no app can see;
- **detection of SIM attacks,** which needs root and modem access, out of stage 1;
- **whether the correction of decision 1 also ships as a Basic 0.1.x release** ahead of 0.2.0.

## Sources

All read on 2026-11-14, unless marked otherwise. AOSP files were read at `refs/heads/main` of the public
repositories on android.googlesource.com, whose last commits were then: `platform/frameworks/opt/telephony`
`307806916047`, `platform/packages/apps/Stk` `b9b03fb5bd5b`, `platform/frameworks/base` `1cdfff555f4a`,
`platform/packages/apps/Settings` `7c598253ff60`, `platform/hardware/interfaces` `1a56e38edc2f`; history across
versions from the `android-*` tags named in the text.

Standards:
- ETSI TS 102 223 V18.3.0 (2026-06), Card Application Toolkit, clauses 6.4.10, 6.4.13, 6.4.15 and 6.4.26:
  https://www.etsi.org/deliver/etsi_ts/102200_102299/102223/18.03.00_60/ts_102223v180300p.pdf
- ETSI TS 102 225 V19.0.0 (2025-11), secured packets:
  https://www.etsi.org/deliver/etsi_ts/102200_102299/102225/19.00.00_60/ts_102225v190000p.pdf
- ETSI TS 102 226 V19.0.0 (2025-11), remote APDU structure, clause 6.1 (minimum security level):
  https://www.etsi.org/deliver/etsi_ts/102200_102299/102226/19.00.00_60/ts_102226v190000p.pdf
- ETSI TS 123 040 V19.0.0 (2025-10), 3GPP TS 23.040, clause 9.2.3.9 (type 0):
  https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/19.00.00_60/ts_123040v190000p.pdf

AOSP:
- `platform/frameworks/opt/telephony`: `src/java/com/android/internal/telephony/cat/CatService.java`,
  `cat/CommandParamsFactory.java`, `gsm/GsmInboundSmsHandler.java`, `uicc/UiccCarrierPrivilegeRules.java`
- `platform/packages/apps/Stk`: `AndroidManifest.xml`, `src/com/android/stk/StkAppService.java`,
  `src/com/android/stk/StkAppInstaller.java`
- `platform/frameworks/base`: `telephony/common/com/android/internal/telephony/CarrierAppUtils.java`,
  `services/core/java/com/android/server/pm/permission/DefaultPermissionGrantPolicy.java`,
  `services/core/java/com/android/server/pm/BackgroundInstallControlService.java`, `core/res/AndroidManifest.xml`,
  `core/res/res/values/config.xml`, `core/java/android/content/pm/PackageManager.java`,
  `telephony/java/android/telephony/TelephonyManager.java`
- `platform/packages/apps/Settings`: `res/values/strings.xml` (`background_install_summary`)
- `platform/hardware/interfaces`: `radio/aidl/android/hardware/radio/sim/IRadioSimIndication.aidl`

Android documentation:
- UICC carrier privileges: https://source.android.com/docs/core/connect/uicc
- `InstallSourceInfo`: https://developer.android.com/reference/android/content/pm/InstallSourceInfo
- `PackageManager`: https://developer.android.com/reference/android/content/pm/PackageManager
- `TelephonyManager`: https://developer.android.com/reference/android/telephony/TelephonyManager

Researchers, vendors and authorities:
- Cathal Mc Daid, AdaptiveMobile Security, Simjacker, Virus Bulletin 2019 slides (2019-10-03):
  https://www.virusbulletin.com/uploads/pdf/conference_slides/2019/VB2019-Mc-Daid.pdf
- Enea, "Simjacker – Next Generation Spying Over Mobile" (2019-09-11):
  https://www.enea.com/insights/simjacker-next-generation-spying-over-mobile/, and its FAQ:
  https://www.enea.com/insights/simjacker-frequently-asked-questions/
- SRLabs, "New SIM attacks de-mystified, protection tools now available", read in the Internet Archive's copy of
  2019-10-22, since the page is gone:
  https://web.archive.org/web/20191022034955/https://srlabs.de/bites/sim_attacks_demystified/
- Ginno Security Lab, WIBattack (2019-09-21), read in the Internet Archive's copy of 2019-10-01:
  https://web.archive.org/web/20191001133057/https://ginnoslab.org/2019/09/21/wibattack-vulnerability-in-wib-sim-browser-can-let-attackers-globally-take-control-of-hundreds-of-millions-of-the-victim-mobile-phones-worldwide-to-make-a-phone-call-send-sms-to-any-phone-numbers/
- Deutscher Bundestag, hib 252/2023 (2023-04-11): https://www.bundestag.de/presse/hib/kurzmeldungen-942244, and
  Drucksache 20/10835 (2024-03-26): https://dserver.bundestag.de/btd/20/108/2010835.pdf
- FBI IC3, PSA I-020822-PSA (2022-02-08): https://www.ic3.gov/PSA/2022/PSA220208
- SEC, on its X account (2024-01-22): https://www.sec.gov/secgov-x-account
- FCC, Report and Order FCC 23-95, WC Docket 21-341, 88 FR 85794 (2023-12-08):
  https://www.govinfo.gov/content/pkg/FR-2023-12-08/html/2023-26338.htm
- NIST SP 800-63B-4, section 3.1.3.3: https://pages.nist.gov/800-63-4/sp800-63b.html
- Lee, Kaiser, Mayer and Narayanan, "An Empirical Study of Wireless Carrier Authentication for SIM Swaps", SOUPS
  2020 (the abstract): https://www.usenix.org/conference/soups2020/presentation/lee
- Guarnieri and Anderson, "Iran and the Soft War for Internet Dominance", Black Hat USA 2016, p. 30:
  https://www.blackhat.com/docs/us-16/materials/us-16-Guarnieri-Iran-And-The-Soft-War-For-Internet-Dominance-wp.pdf
- Digital Turbine, platform description: https://www.digitalturbine.com/dt-platforms-description/
- Telegram FAQ (two-step verification, passkeys, codes): https://telegram.org/faq
- WhatsApp Help Center, two-step verification: https://faq.whatsapp.com/1920866721452534

Signal's Registration Lock page could not be read on 2026-11-14 and is read before decision 3's text cites it.
