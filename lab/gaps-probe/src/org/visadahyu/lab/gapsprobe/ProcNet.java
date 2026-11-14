package org.visadahyu.lab.gapsprobe;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/**
 * proc-net: tries to read the kernel's socket and route tables under /proc/net, and records for each
 * file whether it opened and how many lines it held, or the error. No line's content is kept.
 */
final class ProcNet {
    private ProcNet() {}

    static void run(String step) {
        for (String file : new String[] {"tcp", "tcp6", "udp", "udp6", "unix", "route"}) {
            int lines = 0;
            try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/" + file))) {
                while (reader.readLine() != null) lines++;
                GapsProbe.out("proc-net", step, "file=" + file + " answer=read lines=" + lines);
            } catch (IOException e) {
                GapsProbe.out("proc-net", step, "file=" + file + " answer=refused error=" + GapsProbe.word(e.getMessage()));
            }
        }
    }
}
