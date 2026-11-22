# 0054. Android's own labels, read from the phone

- Status: Accepted (by the maintainer on 2026-11-21, decision 6 of that evening: "**Android's own labels:** read at
  run time from the phone's Settings app resources (as part 3b reads the tools' labels), the translated text as the
  fallback; AOSP's translations checked from its source; the A40's language changed to check Samsung's, restored
  after."). How it is built follows the coordinator's brief and its one audit (2026-11-22).
- Date: 2026-11-22; its fix round, after one review of the code and one of the screens and the coordinator's run on
  the Galaxy A40, the same day.
- Decided by: mehdashti; built by the builder of the labels unit with AI help.
- Builds on: [ADR 0041](0041-visibility-and-coexistence.md), "How the per-tool guides are built", whose way of
  reading another app's labels it shares; [ADR 0030](0030-more-languages-reviewed-by-independent-models.md), to which
  it makes one bounded exception; [ADR 0014](0014-v0.1-permissions.md) (package visibility);
  [ADR 0045](0045-three-editions-of-one-app.md) (the editions); [ADR 0015](0015-dataset-licences.md) and
  [ADR 0017](0017-data-pack-format.md) (datasets and the data pack).

## Context

Datapavan tells people where to find Android's own settings: "turn off USB debugging in developer options", "Look for
Private DNS in the settings that open", "If another VPN app is set to stay always on…", "Remove it under encryption
and credentials", and the plan's buttons, "Usage access", "Install unknown apps". Until now those words were
Datapavan's own, translated with the rest. A label the user cannot find on the screen is a dead end, and W8's settlers
found that some were not what phones show. Read from AOSP's own files at the last tag of each release from Android 10
to 17 (2026-11-22):

- **Text changes far more often than names do.** Under the same resource name, usage access became "App usage data"
  on Android 16; notification access was "Notification access" to 11, "Device & app notifications" on 12 to 14 and
  "Notification read, reply & control" from 15; device admin apps became "Device admin" on 16; Simplified Chinese's
  Private DNS was 私人 DNS to 13 and 专用 DNS from 14; Arabic's always-on VPN changed at 11 and 13.
- **Datapavan's words differed from Android's** in many places: "VPN settings" for a page titled "VPN" in every
  language; "Unused app setting" for the switch "Pause app activity if unused"; Persian's always-on VPN and Private
  DNS, Arabic's always-on VPN, Spanish's usage access, Russian's accessibility; and the always-on switch was only
  paraphrased in eight languages. The full table is in the unit's report.
- **Makers rename settings,** and keep AOSP's resource names in their own Settings, so a name read on a Samsung may
  give AOSP's text that its screen does not show.

## Decision

1. **Android's labels are read from the phone at run time,** as part 3b reads the tools' labels: the system app's
   resources opened without its code (`createPackageContext` with no flags), a configuration for the locales asked, a
   lookup by the resource's name. Nothing is decompiled, and nothing of the system app runs. The shared module's
   `OtherAppResources` does it for both, and `SystemLabels` holds the rules below, so both editions read alike.
2. **In the phone's language, with Datapavan's beside it.** Settings follows the phone's language, so the label is
   read in the phone's languages, region included, which from Android 13 come from `LocaleManager.getSystemLocales()`,
   since an app's own language also changes what `Resources.getSystem()` reports in its process (`PhoneLocales`; W8
   part 3b's guide asks the same way). The region matters: the Galaxy A40's American English says "Optimize
   battery usage" where its bare English, Samsung's British default, says "Optimise". Where Datapavan's language
   differs, language and script both (Traditional Chinese is not Simplified), the label is read in Datapavan's
   language too, in the phone's region for it where the phone has one, and set beside the phone's by a translatable
   pattern, `label_both` ("%1$s (%2$s)", full-width brackets for Chinese). Datapavan's language is the one it shows:
   the first of its configuration's it has words in, else English, so a phone in Hebrew gets English beside its
   label.
3. **Each label keeps the direction of the language it was read in.** AOSP's Persian and Arabic labels that begin with
   a Latin word ("DNS خصوصی") start with a right-to-left mark. Cleaning drops every direction mark (no app's resource
   may turn the sentence around it), so the label is isolated by its language's direction (right to left for Persian
   and Arabic), not by its first strong character, which would lay it out left to right.
4. **The data: where to read each label, by maker and Android version.** `data/android-labels/labels.tsv` (CC0, names
   only) lists for each key the places to try, in order: a maker (`aosp`, or `Build.MANUFACTURER` in lower case) and
   an API range, a package, the resource's type and name, the device a maker's row was seen on, and its source (AOSP's
   repository and the tags its name was read at, or a device). An AOSP row reads Settings, which also holds SettingsLib's
   strings, or the permission controller: Android 11's switch for unused apps is the permission controller's,
   Google's (`com.google.android.permissioncontroller`) on phones with its services and AOSP's otherwise, so two rows
   name both. A row naming the system app that opens an intent was tried and dropped: on Android 11,
   `AUTO_REVOKE_PERMISSIONS` opens Settings' app page, which holds no such label. The phone's maker's rows are tried
   first, then AOSP's. A row whose package is not a system app is skipped, as is a label that is blank, equals its
   resource name or holds a `%`. It is in the signed data pack and read through `DataPackStore.text`, so an imported
   pack's rows win and a maker's names can be added without a release. An imported pack is signed but may be mistaken,
   so its rows are held to the data check's forms: a row that is not well-formed is left out, an AOSP row may name
   only Settings or a permission controller, a key has at most eight rows, a screen reads at most three packages, and
   a read that fails is no label. Today it holds 34 rows for 22 keys: 24 AOSP rows, each name present at every tag of
   its range (no resource in range was renamed), and ten Samsung rows, below.
5. **How a label is worded comes from where it came from.** A label is this phone's own only when it was read
   through its maker's own row, which a device's screen showed, or through AOSP's name on a maker whose Settings show
   AOSP's labels (`SystemLabels.AOSP_MAKERS`: Google, for Pixels and the emulators). On any other maker, a label read
   through AOSP's name is Android's name as that maker's Settings hold it, which its screen may not show; so is the
   fallback. Where a part of a screen names such labels, a line under it names them: "These are Android's own names,
   and your phone may show others: …". The A40's run (2026-11-22, below) showed why: Samsung keeps AOSP's names but
   not always its words ("Usage data access", "Appear on top", "Screen lock type"), and Chinese Private DNS is 私密 DNS
   there, neither of AOSP's.
6. **The fallback is Android's text at the release most phones run, Android 15 (API 35) on 2026-11-22.** Where the
   phone gives no label, the fallback is Datapavan's copy of AOSP's text: in the phone's language where Datapavan has
   it (the rule the restricted-settings label had before), else in Datapavan's own. Where some language's text changes
   after Android 15, a second string holds the later text and is picked by `Build.VERSION.SDK_INT`
   (`android_label_KEY_api36`, `_api37`). Before Android 15 the fallback is Android 15's text, where earlier releases
   differ (notification access on 10 to 14, Chinese Private DNS on 10 to 13), and the line under it says it is Android's
   name. When most phones move to a later release, `FALLBACK_API` in `scripts/android-labels.py` moves, and
   `--write-fallbacks` writes the strings again.
7. **The fallbacks are AOSP's data, not translations: a bounded exception to ADR 0030.** The `android_label_*` strings
   are Android's own words, copied in all eight languages from AOSP's translation of each, each with a comment naming
   the resource and the tag, and never translated by ADR 0030's process: its translators copy them. Spanish's is
   AOSP's `values-es`, Chinese's `values-zh-rCN`, and English's AOSP's `values/`, which is American ("Battery
   optimization"), where Datapavan's own English is British. The exception covers these strings alone; every sentence
   around them is translated as before.
8. **Which strings read a label: the inventory's rule.** A string is kind (a) when the user must find, tap or
   recognise on one of Android's own screens an element whose name it gives: a page, a switch, a button. It reads the
   label in one of two shapes: (a1) the string is the label alone, a button, a heading or an item of a list, and the
   label replaces it; (a2) a sentence quotes it, as a placeholder in the language's quotes, always after a noun (the
   page, the switch, the setting), so that no word around it depends on its gender, number or case. Kind (b) is
   Datapavan's own words that name an idea, which stay translated. Not kind (a): Datapavan's own Settings and buttons,
   the tools' labels (ADR 0041) and other apps' (the Google app's "Hey Google"), and the plain "on its page".
9. **What is kind (a), as built.** In the app module, 15 strings were the label alone and are replaced by it: the
   plan's buttons for accessibility, notification access, install unknown apps, display over other apps, usage access,
   all files access, battery optimisation, VPN and developer options; the special access names display over other
   apps, usage access, install unknown apps and all files access; the phone finding's button to developer options; and
   "Allow restricted settings". Six sentences quote labels and are reshaped: the plan's cards for wireless and USB
   debugging (the switch and its page), for a certificate authority (encryption and credentials), for an app not opened
   that holds sensitive access (the switch for unused apps, only where Android 11 or later offers it for the app; on
   Android 10 and for a system app the card names no switch), the note on device admin apps, and the steps to turn off
   a preinstalled app (Disable). The two steps around restricted settings already took the label as a placeholder.
   The usage access card gains a line with the phone's names for the page and its switch, and "Now" one with the page's
   (point 10). The journal's undo of USB and wireless debugging names the switch as
   Android does. In the network part's module (`:network`), Private DNS's heading is the label alone, and eight
   sentences are reshaped: Android's refusal (always-on VPN), strict Private DNS on the screen, in the chain section
   and in the names' section (Private DNS, Automatic, Off), where to find Private DNS, the limits of strict (always-on
   VPN), a configuration's server by name (Private DNS), and a phone with no screen lock (Screen lock).
10. **Kind (b), with the borderline cases and why.** The plan's button to the switch for unused apps names its page
    ("Unused app setting"), as a button with the switch's words would read as if it paused the app; the card quotes
    the switch. "Device admin" in a list of one app's access stays Datapavan's, as Android's label names the page of
    all such apps; the note on device admin apps quotes it. The plan's buttons for the app's page and for the security
    settings, and the finding's "Open security settings", stay Datapavan's words: the app's page is titled by the
    app's name, and Android does not tell an app whether its security settings open as "Security", "Security &
    privacy" (Safety Center, which Settings itself redirects to) or a maker's own page. So does "Open network
    settings", whose page makers name otherwise ("Connections"), which the line before it says. "Accessibility
    service", "Reads notifications" and "Unrestricted battery use" are Datapavan's descriptions of an access, not
    Android's labels for it. The titles "USB debugging is on" and the plan's short names describe a state; the switch
    is quoted in the card's text. "Open Android's unused apps" and "Open the privacy dashboard" describe the page
    their button opens directly. The review of microphone, camera and location describes the choices on the
    permission controller's page ("asked every time, or deny"), whose words Google Play's system updates change apart
    from the phone's release; a later unit can read them. The proxy "in Android's settings" says where a proxy came
    from and asks nothing of the user. Fourteen strings use "usage access" as Datapavan's name for the access itself
    (`usage_access_body`, `now_no_access` and others), while Android 16 and later name the page "App usage data". The
    maintainer decided on 2026-11-22 to keep Datapavan's name in them and add the phone's own where the user is sent to
    Android's page: the usage access card says "This phone's settings call it “…”, with the switch “…”" (`usage_access`,
    `permit_usage_access`), and "Now", without usage access, "This phone's settings call it "…"".
11. **The licence.** AOSP's strings are Apache-2.0, as Datapavan is, so copying them raises no question of
    compatibility; the labels are a few words each. `NOTICE` says that the `android_label_*` strings and the texts
    the checks compare with are the Android Open Source Project's, from Settings, SettingsLib and the permission
    controller at the tags their comments name. The dataset holds names only, under CC0. Nothing is copied from SD Maid
    SE (GPL-3.0), whose way of scoping labels by ROM and API level this follows. The licences screen needs no new
    entry: its Apache-2.0 text already covers them.
12. **Package visibility costs nothing.** Every edition holds `QUERY_ALL_PACKAGES` for the audit (ADR 0014), so
    every system package is visible, and the manifests change in nothing; the build's check still allows only the
    launcher `<queries>`. If Google Play ever made the Basic edition there drop that permission, one `<package>` query
    per package read would be the way.
13. **The discovery command, for a maker's names.** On debuggable builds only, in both editions and with no VPN
    started, `adb shell dumpsys activity org.visadahyu.datapavan/.MainActivity labels-find LANG [--contains]
    [--package PACKAGE] TEXT` lists the string resources of a system app whose text in a language is TEXT (after
    cleaning and NFC), each with its text in Datapavan's eight languages, so that the coordinator reads a phone's
    screen in one language and changes it only where two names share a text. It enumerates the package's own string
    table by resource ID through Android's API, from the type of the app's own label, and refuses a package that is
    not a system app. `labels-read` prints every label as read in each of the eight languages, each in the phone's own
    region for it where the phone has one, and `-` where nothing was read. Release builds carry neither.
14. **The checks.** `scripts/android-labels.py` (in `scripts/check.sh data`) holds the rows to their form and their
    sources, and every `android_label_*` string, in each language, to AOSP's text at Android 15, or at the later
    release of its variant, as `scripts/testdata/android-labels-aosp.tsv` records it; `--fetch` writes that record
    from AOSP's own files and `--against` checks it again; it also holds each key's first AOSP row to the name its text
    was recorded under, and each row's package to its repository; its self-test catches ten broken copies, each by the
    problem it is about, and runs the fallbacks' writer twice to see it change nothing; the website's two static
    mentions ("Usage access", "USB debugging") are held to the English fallback. `scripts/verify-labels.sh` (the audit
    shard, on CI's Android 15) reads every label in eight languages through the debug dump and compares each with
    AOSP's text at the emulator's own release, where a known difference names why (three texts of Android 15's first
    build, one of Android 11's), then checks the screens with the phone in English and Datapavan in Persian, and the
    other way round. It passed on Android 10, 11, 15 and 17 emulators on 2026-11-22. JVM tests cover each rule.
15. **Samsung, read on a device.** The coordinator ran `labels-read` on a Galaxy A40 (SM-A405FN, One UI 3, Android 11,
    build A405FNXXU4CWC3) on 2026-11-22: every key read from Settings by AOSP's names, and the screen showed the text
    read for ten of them in English (usage access, display over other apps, battery optimisation, notification access,
    all files access, install unknown apps, VPN, accessibility, developer options, USB debugging). Those ten are
    `samsung` rows for Android 11, verified on that build, so on it they are the phone's own. Private DNS, device admin
    apps, encryption and credentials and screen lock were not seen on the screen and stay Android's names there, with
    the note, as does every label on other Android versions of Samsung's.

## Consequences

- **Labels match the phone on AOSP's makers today, and on others as their rows arrive.** On a Pixel or an emulator
  the labels are the phone's own; on Samsung's Android 11, ten are; elsewhere they are AOSP's names as each maker's
  Settings hold them, and the screen names them as Android's until the coordinator reads them on a device. Only a
  Google phone and rows the data has verified on a screen say nothing more.
- **Limits.**
  - A maker whose label the data lacks shows AOSP's text as its Settings hold it, which its screen may not show; the
    screen then names it as Android's.
  - `Build.MANUFACTURER` names the maker, not the system: MIUI and HyperOS are both `xiaomi`, and a custom system on a
    Xiaomi phone gets MIUI's rows first. A maker's row with an API range of its own keeps the two apart where they
    differ by version.
  - A label a maker moved to another screen is still named, but the steps around it ("on the developer options
    page") may lead elsewhere.
  - Settings in a language Datapavan lacks is read in that language, with Datapavan's beside it; the fallback there
    is in Datapavan's language.
  - A string a maker keeps outside its Settings' own table (a shared resource library) is not read; nor are labels
    a maker's Settings write in code.
  - The permission controller updates through Google Play's system updates, so its texts are not those of the
    phone's release; Android 11's switch for unused apps is the only label read from it.
  - Translations are revised within a release, too: Android 15's emulator image of August 2024 shows
    android-15.0.0_r1's Chinese accessibility and notification access and Persian developer options, which later
    tags of 15 revised. A phone on an early build reads its own text; only its fallback would be the later one.
  - Only the emulators' builds and one Samsung build are checked; other makers wait for a device.
  - Reading costs Settings' resource table, about 2.7 MB of PSS in the network part's process (`:network`) with its
    screen open on the Android 15 emulator, within its memory budget of 48 MB. The network part reads the data pack's
    rows on a thread of its own, and shows Datapavan's copies until they are read, with no note meanwhile.
- **Reading costs little.** Settings' resource table is opened once per screen, when the first label is asked for,
  and its strings are read by name.
- **The translators' work changes shape.** A reshaped sentence takes a placeholder after a noun; the labels themselves
  are copied, not translated.
