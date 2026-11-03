# 0026. The remediation plan in v0.1

- Status: Proposed
- Date: 2026-11-03
- Decided by: mehdashti

## Context
[REMEDIATION.md](../REMEDIATION.md) designs the remediation plan for every privilege level: a short queue
of actions ordered by how much risk each removes, three levels, a journal with undo, and a safety
floor. M5 builds the part that an ordinary app can do. Research for the design (in the project's
private research, 2026-10-30) found:

- **An ordinary app proposes; the system acts.** Without root, an ADB bridge or a device-policy role,
  an app can only open system screens: App info, the per-app setting for unused apps (Android 11+),
  the screens of special access, and the uninstall confirmation with the normal permission
  `REQUEST_DELETE_PACKAGES`. It cannot disable, suspend or hide another app, or revoke its
  permissions.
- **Tools that remove apps delete their data.** The common debloaters clear data when they disable
  and uninstall without keeping data, keep a snapshot rather than a journal, and none of them checks
  afterwards whether the phone still works. Their package ratings carry no tests per model, and
  packages they rated safe have stopped phones from starting.
- **Users accept recommendations, and stop reading after the second card.** People adopted about four
  in five recommendations of a privacy assistant (Liu et al., SOUPS 2016), and attention to repeated
  warnings drops after the second one (Anderson et al., CHI 2015). One breakage turns people against
  later security actions (Vaniea et al., CHI 2014).
- **Necessity cannot be inferred.** No published method tells reliably whether an app needs a
  permission. The strong signals are an app not opened for months that still holds sensitive access,
  and a tracker's purpose.
- **Stalkerware needs care.** Changing it can alert the person who installed it (Havron et al., USENIX
  Security 2019).

Android's Safety Center, the closest platform precedent, orders its issues by severity and gives each
one an action; it has no journal of what the user changed and no undo.

## Decision
1. **Only hand-offs.** In v0.1 every action opens a system screen where the user decides, and
   Datapavan changes nothing itself:
   - App info, for permissions, disabling, stopping and uninstalling;
   - on Android 11 and later, the app's setting for unused apps (`ACTION_AUTO_REVOKE_PERMISSIONS`);
   - the screen of the special access concerned: the app's own page where Android offers one
     (installing unknown apps, all-files access, a notification listener), otherwise the list
     (accessibility, overlay, usage access, battery optimisation, device admins under Security);
   - for the phone: developer options, security settings for certificate authorities, VPN settings.

   **No uninstall dialog of Datapavan's own.** `REQUEST_DELETE_PACKAGES` is not requested: an uninstall
   deletes the app's data, which REMEDIATION.md forbids Datapavan to start. App info offers it one tap
   further when the user chooses it, and the card says that the app's data goes with it. ADR 0014
   stays as it is, and the consequence that ADR 0022 left open is closed.
2. **What enters the queue.** An item is a finding with a screen that can remove it:
   - **the phone:** wireless debugging on, a user-installed certificate authority, USB debugging on;
   - **control:** a VPN app with access that can control the phone, and any other app installed by
     the user with that access (accessibility, notification listener, device admin);
   - **a doubtful copy:** an app that is modified, or that carries an untrusted system key, against
     the official list (ADR 0018, ADR 0023);
   - **installing apps:** an app installed by the user that may install other apps;
   - **traffic sharing:** an app that contains a traffic-sharing SDK (ADR 0019);
   - **not opened for 90 days** (ADR 0022) and still holding a sensor permission, special access, VPN
     permission, another sensitive permission, or background data use;
   - **at the strict level only,** preinstalled apps not opened for 90 days and preinstalled data
     collectors, through App info, where Android itself decides whether they can be disabled.

   A tracker alone never makes an item; it raises the item's place. The facts of ADR 0025 and the
   sensor access of apps in use stay on the app pages and in the strict sensor review.
3. **Order by what the action removes, with no score.** Items fall into three classes, and the queue
   shows them class by class:
   - **A, control of the phone or its traffic:** wireless debugging, a certificate authority, control
     access, a doubtful copy;
   - **B, data or code moving without the user:** an app not opened for 90 days that holds a sensor,
     special access or VPN permission, installing apps, traffic sharing, USB debugging;
   - **C, the rest:** an app not opened for 90 days that holds another sensitive permission or
     background data use, and the strict level's preinstalled apps.

   Within a class: items whose app contains advertising, analytics or profiling trackers first, then
   the longest time not opened, then the reason in the order above, then the name. A numeric score would claim a precision that nobody has
   measured; Safety Center orders by severity in the same way.
4. **Three levels, which differ in what they include:**
   - **Light** (the default): class A, and apps not opened for 90 days that hold a sensor, special
     access or VPN permission.
   - **Medium:** all of classes A and B, and apps not opened for 90 days that hold another sensitive
     permission or used data in the background.
   - **Strict:** everything above, and preinstalled apps through App info. Each preinstalled item
     says that Datapavan has not tested it on this phone, what may stop working, and that it can be
     enabled again on the same screen, and it needs one extra confirmation.

   REMEDIATION.md's evidence rules apply to steps that Datapavan applies itself (an ADB bridge or the
   Device Owner edition); in v0.1 Android's App info decides what can be disabled. As the lab's tests
   arrive, tested items move to lower levels.
5. **A safety floor that no level lowers.** These apps never become items; their findings stay on
   their pages, and the plan lists them as left alone, with the reason:
   - computed on the phone at every run: the home screen, the default phone, SMS and browser apps,
     every enabled keyboard, accessibility services that speak or show braille while a screen reader
     is on, the device or profile owner, preinstalled device admins, the package installer and the
     permission controller, and Datapavan;
   - a deny-list by function in `data/remediation/floor.tsv` (CC0, in the signed data pack): start-up
     and core services, calls, mobile data, SIM and eSIM, emergency alerts and information, system
     and app updates, setup, time-zone data, connectivity, and device-locking and anti-theft
     components. Each row names the function and its source. Community debloat lists are not
     copied (ADR 0015).
6. **Care with control access.** Before the hand-off of an item about control access, the card says
   that if someone else may have installed the app to watch the user, changing it can alert that
   person, and that help exists; the user continues with one more tap. This is the only extra step
   apart from the strict level's preinstalled items.
7. **A short session.** The user starts the plan; nothing starts it for them, and Datapavan sends no
   notifications. The overview names the first action, never a count of problems. A session shows at
   most five cards; the rest wait for the next session. The user can skip a card or keep the app as
   it is, and both go into the journal. A session ends with what changed and what was kept.
8. **A journal of what actually changed.** For each card the user acts on, Datapavan records the time,
   the item, the screen it opened, and the state that the item concerns before and after (the
   permissions, special access, VPN permission, whether the app is enabled and installed), read again
   when the user comes back. It records what actually happened: "camera removed", "disabled",
   "uninstalled", "nothing changed".
   - **Undo** opens the same screen and says what to turn back on. For an uninstalled app it says
     that Datapavan cannot bring it back and that its data is gone.
   - **At every start,** and so after every restart, the journal compares the current state with
     what it recorded and says where something came back, for example after an update.
   - **Three days after a session,** the plan asks once whether everything still works. "Something is
     wrong" lists that session's changes with their undo.
   - The journal is kept in app-private storage, excluded from backups like all of Datapavan's data,
     holds package names and state flags only, and can be deleted with one tap. Nothing leaves the
     phone (ADR 0016).

## Consequences
- No new permission. The privacy policy describes the journal.
- `data/remediation/floor.tsv` joins the data pack with its licence and source files, and the data
  check covers it.
- Rules and ordering are pure functions with unit tests; an end-to-end script drives the plan on the
  emulator with the fixture app, as `scripts/verify-audit.sh` does.
- REMEDIATION.md, DESIGN.md, the roadmap and the changelog describe v0.1's plan as built.
- What v0.1 cannot do: apply anything itself, read Android's hibernation state, or know whether a
  preinstalled app can be disabled before App info shows it. A preinstalled app disabled on App info
  can still break something Datapavan does not know of; the journal, the check after three days and
  the floor are what limit that, and lab tests per model are what will narrow it.
