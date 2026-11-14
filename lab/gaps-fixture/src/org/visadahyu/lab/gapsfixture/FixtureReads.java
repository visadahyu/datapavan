package org.visadahyu.lab.gapsfixture;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.BaseColumns;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.provider.Telephony;

/**
 * The reads of the indicators behaviour. Each asks only for the rows' ids, never a value, and records
 * whether the read happened and how many rows it returned.
 */
final class FixtureReads {
    private FixtureReads() {}

    static void read(Context context, String kind) {
        Uri uri;
        switch (kind) {
            case "contacts": uri = ContactsContract.Contacts.CONTENT_URI; break;
            case "calllog": uri = CallLog.Calls.CONTENT_URI; break;
            case "sms": uri = Telephony.Sms.CONTENT_URI; break;
            default: uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI; break;
        }
        try (Cursor rows = context.getContentResolver().query(uri, new String[] {BaseColumns._ID}, null, null, null)) {
            GapsFixture.out("read kind=" + kind + " answer=read count=" + (rows == null ? 0 : rows.getCount()));
        } catch (RuntimeException e) {
            GapsFixture.out("read kind=" + kind + " answer=refused error=" + e.getClass().getSimpleName());
        }
    }

    static void clipboard(Context context) {
        ClipData clip = context.getSystemService(ClipboardManager.class).getPrimaryClip();
        GapsFixture.out("read kind=clipboard answer=" + (clip == null ? "empty count=0" : "read count=" + clip.getItemCount()));
    }
}
