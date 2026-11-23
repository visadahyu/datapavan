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
 * Every language is "available", so that the screen reader hands it text in any language and says which; the global
 * setting datapavan_speechlog_without leaves some out, to see what a screen reader does without a voice for them.
 *
 *   adb shell settings put secure tts_default_synth org.visadahyu.datapavan.speechlog
 */
public class SpeechLogService extends TextToSpeechService {
    static final String TAG = "DatapavanSpeech";
    private String[] language = {"eng", "USA", ""};

    // Every language is available, at the level the request names: Android's default list of voices keeps a locale only
    // when the answer matches how specific it is, and a screen reader switches only to a language with a voice.
    @Override
    protected int onIsLanguageAvailable(String lang, String country, String variant) {
        // To measure what a screen reader does when the engine has no voice for a language, as Google's engine has
        // none for Persian: adb shell settings put global datapavan_speechlog_without fas,ara (ISO 639-2 codes).
        String without = android.provider.Settings.Global.getString(getContentResolver(), "datapavan_speechlog_without");
        if (without != null && lang != null) {
            String code;
            try {
                code = new java.util.Locale(lang).getISO3Language();
            } catch (java.util.MissingResourceException e) {
                code = lang;
            }
            for (String left : without.split(",")) {
                if (left.trim().equalsIgnoreCase(code)) return TextToSpeech.LANG_NOT_SUPPORTED;
            }
        }
        if (variant != null && !variant.isEmpty()) return TextToSpeech.LANG_COUNTRY_VAR_AVAILABLE;
        if (country != null && !country.isEmpty()) return TextToSpeech.LANG_COUNTRY_AVAILABLE;
        return TextToSpeech.LANG_AVAILABLE;
    }

    @Override
    protected String[] onGetLanguage() {
        return language;
    }

    @Override
    protected int onLoadLanguage(String lang, String country, String variant) {
        language = new String[] {lang, country == null ? "" : country, variant == null ? "" : variant};
        Log.i(TAG, "load language " + lang + "-" + country);
        return onIsLanguageAvailable(lang, country, variant);
    }

    @Override
    public int onLoadVoice(String voiceName) {
        Log.i(TAG, "load voice " + voiceName);
        return super.onLoadVoice(voiceName);
    }

    @Override
    protected void onStop() {
    }

    @Override
    protected void onSynthesizeText(SynthesisRequest request, SynthesisCallback callback) {
        CharSequence text = request.getCharSequenceText();
        String said = text == null ? request.getText() : text.toString();
        String voice = request.getVoiceName();
        Log.i(TAG, request.getLanguage() + "-" + request.getCountry() + (voice == null || voice.isEmpty() ? "" : " voice " + voice)
            + "\t" + (said == null ? "" : said.replace('\n', ' ')));
        // Ten milliseconds of silence, so that every request ends as a spoken one: a screen reader moves to another
        // engine after failures.
        callback.start(16000, AudioFormat.ENCODING_PCM_16BIT, 1);
        byte[] silence = new byte[320];
        callback.audioAvailable(silence, 0, silence.length);
        callback.done();
    }
}
