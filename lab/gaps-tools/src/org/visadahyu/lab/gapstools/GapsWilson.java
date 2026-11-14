package org.visadahyu.lab.gapstools;

import java.util.Locale;

/**
 * Wilson's score interval for a rate (ADR 0048, decision 2): the 95 % interval for k events in n trials,
 * which stays inside 0 to 1 and does not collapse to a point at 0 or n, as the normal approximation does.
 */
final class GapsWilson {
    private static final double Z = 1.959963984540054;

    private GapsWilson() {}

    static double[] interval(int events, int trials) {
        if (trials <= 0 || events < 0 || events > trials) throw new IllegalArgumentException(events + " of " + trials);
        double n = trials;
        double p = events / n;
        double z2 = Z * Z;
        double centre = (p + z2 / (2 * n)) / (1 + z2 / n);
        double half = Z * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n);
        return new double[] {Math.max(0, centre - half), Math.min(1, centre + half)};
    }

    /** The interval as the CSV writes it: "0.012-0.071". */
    static String format(int events, int trials) {
        double[] range = interval(events, trials);
        return String.format(Locale.ROOT, "%.3f-%.3f", range[0], range[1]);
    }

    static String rate(int events, int trials) {
        return String.format(Locale.ROOT, "%.3f", events / (double) trials);
    }
}
