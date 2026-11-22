# 0054. Android's own labels, read from the phone

- Status: Accepted (by the maintainer on 2026-11-21, decision 6 of that evening: "**Android's own labels:** read at
  run time from the phone's Settings app resources (as part 3b reads the tools' labels), the translated text as the
  fallback; AOSP's translations checked from its source; the A40's language changed to check Samsung's, restored
  after."). How it is built follows the coordinator's brief and its one audit (2026-11-22).
- Date: 2026-11-22
- Decided by: mehdashti; built by the builder of the labels unit with AI help.
- Builds on: [ADR 0041](0041-watch-visibility-and-coexistence.md), "How the per-tool guides are built", whose way of
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
   read in the phone's languages, which from Android 13 come from `LocaleManager.getSystemLocales()`, since an app's
   own language also changes what `Resources.getSystem()` reports in its process (`PhoneLocales`; W8 part 3b's guide
   now asks the same way). Where Datapavan's language differs, language and script both (Traditional Chinese is not
   Simplified), the label is read in Datapavan's language too and set beside the phone's by a translatable pattern,
   `label_both` ("%1$s (%2$s)", full-width brackets for Chinese).
3. **Each label keeps the direction of the language it was read in.** AOSP's Persian and Arabic labels that begin with
   a Latin word ("DNS خصوصی") start with a right-to-left mark. Cleaning drops every direction mark (no app's resource
   may turn the sentence around it), so the label is isolated by its language's direction (right to left for Persian
   and Arabic), not by its first strong character, which would lay it out left to right.
4. **The data: where to read each label, by maker and Android version.** `data/android-labels/labels.tsv` (CC0, names
   only) lists for each key the places to try, in order: a maker (`aosp`, or `Build.MANUFACTURER` in lower case) and
   an API range, a package or `handler:ACTION` (the system app Android opens that intent with: Android 11's switch for
   unused apps is the permission controller's, `com.google.android.permissioncontroller` on phones with Google's
   services), the resource's type and name, the device a maker's row was seen on, and its source (AOSP's repository and
   the tags its name was read at, or a device). The phone's maker's rows are tried first, then AOSP's. A row whose
   package is not a system app is skipped, as is a label that is blank, equals its resource name or holds a `%`. It is
   in the signed data pack and read through `DataPackStore.text`, so an imported pack's rows win and a maker's names
   can be added without a release. Today it holds 22 rows for 21 keys, all AOSP's, each name present at every tag of
   its range: no resource in range was renamed.
5. **How a label is worded comes from where it came from.** A label read through the maker's own row, seen on a
   screen, or through AOSP's name on a maker that has no row at all, is this phone's. One read through AOSP's name on a
   maker whose rows cover other labels only is Android's name as that maker's Settings hold it, which its screen may
   not show; so is the fallback. Where a part of a screen quotes such a label, a line under it says that the words in
   quotes are Android's own names and that the phone may name them differently.
6. **The fallback is Android's text at the release most phones run, Android 15 (API 35) on 2026-11-22.** Where the
   phone gives no label, the fallback is Datapavan's copy of AOSP's text: in the phone's language where Datapavan has
   it (the rule the restricted-settings label had before), else in Datapavan's own. Where some language's text changes
   after Android 15, a second string holds the later text and is picked by `Build.VERSION.SDK_INT`
   (`android_label_KEY_api36`, `_api37`). When most phones move to a later release, `FALLBACK_API` in
   `scripts/android-labels.py` moves, and `--write-fallbacks` writes the strings again.
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
9. **What is kind (a), as built.** In the app module, 17 strings were the label alone and are replaced by it: the
   plan's buttons for unused apps, accessibility, notification access, install unknown apps, display over other
   apps, usage access, all files access, battery optimisation, VPN and developer options; the special access names
   device admin, display over other apps, usage access, install unknown apps and all files access; the phone finding's
   button to developer options; and "Allow restricted settings". Six sentences quote labels and are reshaped: the
   plan's cards for wireless and USB debugging (the switch and its page), for a certificate authority (encryption and
   credentials), for an app not opened that holds sensitive access (the switch for unused apps), the note on device
   admin apps, and the steps to turn off a preinstalled app (Disable). The two steps around restricted settings
   already took the label as a placeholder. The journal's undo of USB and wireless debugging names the switch as
   Android does. In the network monitoring's module, Private DNS's heading is the label alone, and eight sentences are
   reshaped: Android's refusal (always-on VPN), strict Private DNS on the screen, in the chain section and in the
   names' section (Private DNS, Automatic, Off), where to find Private DNS, the limits of strict (always-on VPN), a
   configuration's server by name (Private DNS), and a phone with no screen lock (Screen lock).
10. **Kind (b), with the borderline cases and why.** The plan's buttons for the app's page and for the security
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
    from and asks nothing of the user. Fourteen strings reuse the words "usage access" for the access itself
    (`usage_access_body`, `now_no_access` and others): they stay as they are in this unit, a question for the
    maintainer, since on Android 16 and later the phone names the setting "App usage data".
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
    not a system app. `labels-read` prints every label as read in each of the eight languages. Release builds carry
    neither.
14. **The checks.** `scripts/android-labels.py` (in `scripts/check.sh data`) holds the rows to their form and their
    sources, and every `android_label_*` string, in each language, to AOSP's text at Android 15, or at the later
    release of its variant, as `scripts/testdata/android-labels-aosp.tsv` records it; `--fetch` writes that record
    from AOSP's own files and `--against` checks it again; its self-test catches seven broken copies; the website's
    two static mentions ("Usage access", "USB debugging") are held to the English fallback. `scripts/verify-labels.sh`
    (the audit shard, on CI's Android 15) reads every label in eight languages through the debug dump and compares
    each with AOSP's text at the emulator's own release, then checks the screens with the phone in English and
    Datapavan in Persian, and the other way round. JVM tests cover each rule.

## Consequences

- **Labels match the phone on AOSP's makers today, and on others as their rows arrive.** On a Pixel or an emulator
  the labels are the phone's own; on Samsung, Xiaomi or Oppo they are AOSP's names as their Settings hold them until
  the coordinator reads their names on a device. Only rows the data has verified on a screen say nothing more.
- **Limits.**
  - A maker whose label the data lacks shows AOSP's text as its Settings hold it, which its screen may not show;
    once the maker has rows for other labels, the screen says such a label is Android's name.
  - A label a maker moved to another screen is still named, but the steps around it ("on the developer options
    page") may lead elsewhere.
  - Settings in a language Datapavan lacks is read in that language, with Datapavan's beside it; the fallback there
    is in Datapavan's language.
  - A string a maker keeps outside its Settings' own table (a shared resource library) is not read; nor are labels
    a maker's Settings write in code.
  - The permission controller updates through Google Play's system updates, so its texts are not those of the
    phone's release; Android 11's switch for unused apps is the only label read from it.
  - Only an emulator's builds are checked today; the A40 (SM-A405FN) is the coordinator's to read.
- **Reading costs little.** Settings' resource table is opened once per screen, when the first label is asked for,
  and its strings are read by name.
- **The translators' work changes shape.** A reshaped sentence takes a placeholder after a noun; the labels themselves
  are copied, not translated.
