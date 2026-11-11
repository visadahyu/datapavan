package org.visadahyu.datapavan.testtool;

import android.app.Activity;
import android.os.Bundle;

/** A launcher entry only, so that Watch can see the test tool as it sees the apps a user can open. */
public final class ToolActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        finish();
    }
}
