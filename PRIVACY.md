# Privacy policy

**Datapavan collects no data about you. None.**

## What this means in practice

- **No analytics, no crash reporting, no telemetry.** The app contains no third-party SDKs that could send data.
- **No accounts.** You never sign up and never give us anything.
- **No servers that receive user data.** The project does not operate one.
- **Everything stays on your phone.** All analysis happens on the device. Datapavan's own data lives in app-private storage, encrypted where it records network activity.
- **No backups leave the phone.** Android cloud backup and device-to-device transfer are disabled for Datapavan's data.
- **Uninstalling deletes everything.** Nothing remains anywhere.

## Version 0.1 cannot send anything

Version 0.1 ("Audit") does not request the INTERNET permission. Android itself prevents it from using
the network, and the build fails if any component tries to add that permission.

## Permissions and why they are needed

| Permission | Used for | From |
|---|---|---|
| See installed apps | Listing apps and their permissions | v0.1 |
| Usage access (granted by you in Settings) | Showing how much data each app has sent | v0.1 |
| VPN (granted by you) | The **local** firewall. Traffic is filtered on the phone and never sent to us | v0.2 |
| Internet | Forwarding the traffic of other apps through the local firewall, and optional list updates | v0.2 |

## Optional updates of tracker lists (from v0.2)

If you turn this on, Datapavan downloads signed tracker lists from a public mirror. Like any download,
this reveals your IP address and the time of the request to the mirror's operator. It reveals nothing
about your phone, your apps or your activity. You can turn updates off and import list files manually.

## Contact

Questions about this policy: open an issue on Codeberg, or use the security contact in
[SECURITY.md](SECURITY.md) for anything sensitive.
