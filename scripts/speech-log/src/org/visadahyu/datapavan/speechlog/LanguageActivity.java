package org.visadahyu.datapavan.speechlog;

import android.app.Activity;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.LocaleSpan;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.Locale;

/**
 * Whether a screen reader takes a text's language from a LocaleSpan (the accessibility unit's walk): three lines of
 * Persian, the first plain, the second marked as Persian with a LocaleSpan, the third marked as Arabic; the speech log
 * then says which language the screen reader asked for each.
 *
 *   adb shell am start -n org.visadahyu.datapavan.speechlog/.LanguageActivity
 */
public class LanguageActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(48, 160, 48, 48);
        column.addView(line("یک: بدون برچسب زبان", null));
        column.addView(line("دو: با برچسب فارسی", Locale.forLanguageTag("fa-IR")));
        column.addView(line("سه: با برچسب عربی", Locale.forLanguageTag("ar")));
        // A language's name between isolates, marked whole, and marked inside the isolates only.
        column.addView(line("\u2068Русский\u2069", Locale.forLanguageTag("ru")));
        column.addView(inside("\u2068Русский\u2069", Locale.forLanguageTag("ru")));
        setContentView(column);
    }

    private TextView inside(String text, Locale locale) {
        TextView view = line(text, null);
        SpannableString marked = new SpannableString(text);
        marked.setSpan(new LocaleSpan(locale), 1, text.length() - 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        view.setText(marked);
        return view;
    }

    private TextView line(String text, Locale locale) {
        TextView view = new TextView(this);
        view.setTextSize(24);
        view.setPadding(0, 32, 0, 32);
        if (locale == null) {
            view.setText(text);
        } else {
            SpannableString marked = new SpannableString(text);
            marked.setSpan(new LocaleSpan(locale), 0, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            view.setText(marked);
        }
        return view;
    }
}
