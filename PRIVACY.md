# Privacy policy

- **Effective:** 2026-10-29
- **Responsible:** the Datapavan maintainer (mehdashti), until the Visadahyu Foundation is established

**Datapavan collects no data about you.**

## What this means in practice

- **No analytics, no crash reporting, no telemetry.** The app contains no third-party SDKs that could send data.
- **No accounts.** You never sign up and never give us anything.
- **No servers that receive user data.** The project does not operate any.
- **Everything stays on your phone.** All analysis happens on the device. Datapavan's own data lives in app-private storage, encrypted where it records network activity.
- **No backups leave the phone.** Android cloud backup and device-to-device transfer are disabled for Datapavan's data.
- **Uninstalling deletes Datapavan's data.** The only exception is files you exported yourself, for example a report you saved to shared storage.

## Version 0.1 cannot open network connections

Version 0.1 ("Audit") does not request the INTERNET permission, so Android itself prevents it from
opening network connections. The build fails if any component tries to add that permission. Like any
app, it can still hand information to another app when you ask it to, for example when you open a link
or share a report.

## Permissions and why they are needed

| Permission | Used for | From |
|---|---|---|
| See installed apps | Listing apps and their permissions | v0.1 |
| Usage access (granted by you in Settings) | Showing how much data each app has sent | v0.1 |
| VPN (granted by you) | The **local** firewall. Traffic is filtered on the phone and never sent to us | v0.2 |
| Internet | Forwarding the traffic of other apps through the local firewall, and optional list updates | v0.2 |

## Optional updates of tracker lists (from v0.2)

If you turn this on, Datapavan downloads signed tracker lists from a public mirror. Like any download:

- the mirror's operator sees your IP address and the time of the request;
- the operator, and anyone observing your network, can tell that the device uses Datapavan.

The request contains nothing about your phone, your apps or your activity. Updates are signed, and older
lists are never accepted in place of newer ones. You can turn updates off and import list files
manually. Once mirrors exist, this policy will name each operator, and say what it logs and for how long.

## Contact

Questions about this policy: open an issue on Codeberg. For anything sensitive, use the security
contact in [SECURITY.md](SECURITY.md).
