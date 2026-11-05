package org.visadahyu.datapavan.ui

/**
 * The screens that the launcher shortcuts open (ROADMAP, v0.1; `res/xml/shortcuts.xml`): a long press
 * on the app's icon goes straight to the plan, the apps or network use. Each shortcut's intent carries
 * one of these actions, and `ShortcutsTest` checks that the file and this list agree.
 *
 * MainActivity is exported for the launcher, so any app can send these actions too. They only choose
 * a screen of the app; nothing is changed or returned.
 */
enum class LaunchTarget(val action: String) {
    PLAN("org.visadahyu.datapavan.action.OPEN_PLAN"),
    APPS("org.visadahyu.datapavan.action.OPEN_APPS"),
    NETWORK("org.visadahyu.datapavan.action.OPEN_NETWORK"),
    ;

    companion object {
        /** The target of an intent's action, or null for any other start, such as the launcher icon. */
        fun of(action: String?): LaunchTarget? = entries.firstOrNull { it.action == action }
    }
}
