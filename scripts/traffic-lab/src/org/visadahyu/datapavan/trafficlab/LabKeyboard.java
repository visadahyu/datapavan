package org.visadahyu.datapavan.trafficlab;

import android.inputmethodservice.InputMethodService;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.TextView;

/**
 * A keyboard for the keyboard spike (docs/spikes/2026-11-keyboard-counting.md): while it is shown it
 * downloads SHOWN bytes, and HIDDEN_DELAY_MS after it is hidden it downloads HIDDEN bytes, from the
 * emulator host's server.py. The two amounts tell in Android's counts which state each was counted in.
 */
public final class LabKeyboard extends InputMethodService {
    static final long SHOWN = 3_000_000;
    static final long HIDDEN = 7_000_000;
    private static final long HIDDEN_DELAY_MS = 20_000;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean shownDone;
    private boolean hiddenDone;

    /** Shown even where the emulator has a hardware keyboard, which hides on-screen keyboards by default. */
    @Override
    public boolean onEvaluateInputViewShown() {
        super.onEvaluateInputViewShown();
        return true;
    }

    @Override
    public View onCreateInputView() {
        Log.i(Transfer.TAG, "keyboard view created");
        TextView view = new TextView(this);
        view.setText("Datapavan lab keyboard");
        view.setPadding(48, 96, 48, 96);
        return view;
    }

    @Override
    public void onStartInputView(EditorInfo info, boolean restarting) {
        super.onStartInputView(info, restarting);
        Log.i(Transfer.TAG, "keyboard shown");
        if (shownDone) return;
        shownDone = true;
        new Thread(() -> Transfer.run(null, SHOWN, 0)).start();
    }

    @Override
    public void onFinishInputView(boolean finishingInput) {
        super.onFinishInputView(finishingInput);
        Log.i(Transfer.TAG, "keyboard hidden");
        if (!shownDone || hiddenDone) return;
        hiddenDone = true;
        handler.postDelayed(() -> new Thread(() -> Transfer.run(null, HIDDEN, 0)).start(), HIDDEN_DELAY_MS);
    }
}
