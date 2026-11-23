package org.visadahyu.datapavan.speechlog;

import android.media.AudioFormat;
import android.speech.tts.SynthesisCallback;
import android.speech.tts.SynthesisRequest;
import android.speech.tts.TextToSpeech;
import android.speech.tts.TextToSpeechService;
import android.util.Log;

/**
 * A speech engine that speaks nothing: each utterance a screen reader hands it goes to logcat under the tag
 * DatapavanSpeech, as "LANGUAGE-COUNTRY TAB TEXT" (line breaks become spaces), and the utterance ends at once.
 * Every language is "available", so that the screen reader hands it text in any language and says which.
 *
 *   adb shell settings put secure tts_default_synth org.visadahyu.datapavan.speechlog
 */
public class SpeechLogService extends TextToSpeechService {
    static final String TAG = "DatapavanSpeech";
    private String[] language = {"eng", "USA", ""};

    @Override
    protected int onIsLanguageAvailable(String lang, String country, String variant) {
        return TextToSpeech.LANG_COUNTRY_VAR_AVAILABLE;
    }

    @Override
    protected String[] onGetLanguage() {
        return language;
    }

    @Override
    protected int onLoadLanguage(String lang, String country, String variant) {
        language = new String[] {lang, country == null ? "" : country, variant == null ? "" : variant};
        return TextToSpeech.LANG_COUNTRY_VAR_AVAILABLE;
    }

    @Override
    protected void onStop() {
    }

    @Override
    protected void onSynthesizeText(SynthesisRequest request, SynthesisCallback callback) {
        CharSequence text = request.getCharSequenceText();
        String said = text == null ? request.getText() : text.toString();
        Log.i(TAG, request.getLanguage() + "-" + request.getCountry() + "\t" + (said == null ? "" : said.replace('\n', ' ')));
        // Ten milliseconds of silence, so that every request ends as a spoken one: a screen reader moves to another
        // engine after failures.
        callback.start(16000, AudioFormat.ENCODING_PCM_16BIT, 1);
        byte[] silence = new byte[320];
        callback.audioAvailable(silence, 0, silence.length);
        callback.done();
    }
}
