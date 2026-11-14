package org.visadahyu.lab.gapsfixture;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import java.util.Arrays;

/** Records one second from the microphone into memory, then drops it: only the byte count is recorded. */
final class FixtureMicrophone {
    private FixtureMicrophone() {}

    static void record() {
        int rate = 16_000;
        byte[] second = new byte[rate * 2];
        int total = 0;
        try {
            int size = Math.max(AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT), second.length);
            AudioRecord recorder = new AudioRecord(MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT, size);
            try {
                recorder.startRecording();
                while (total < second.length) {
                    int n = recorder.read(second, total, second.length - total);
                    if (n <= 0) break;
                    total += n;
                }
                recorder.stop();
            } finally {
                recorder.release();
            }
            GapsFixture.out("read kind=mic answer=read count=" + total);
        } catch (RuntimeException e) {
            GapsFixture.out("read kind=mic answer=refused error=" + e.getClass().getSimpleName());
        } finally {
            Arrays.fill(second, (byte) 0);
        }
    }
}
