import java.lang.management.ManagementFactory;
import javax.management.ObjectName;

public class HotspotStack {
    static native void arm();
    static native long probe(long value);

    static long leaf(long x) { return probe(x) + 1; }

    // Keep arguments live across the call so the caller needs a different
    // frame layout from leaf on both supported architectures.
    static long middle(long x, long a, long b, long c, long d, long e,
                       long f, long g, long h, long i, long j, long k) {
        return leaf(x) + a + b + c + d + e + f + g + h + i + j + k;
    }

    static long outer(long x) {
        return middle(x, x+1, x+2, x+3, x+4, x+5, x+6, x+7, x+8, x+9, x+10, x+11);
    }

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        long value = 0;
        for (int i = 0; i < 200_000; i++) value = outer(value);

        // Independent ground truth from HotSpot for the compiled code ranges.
        var commands = new ObjectName("com.sun.management:type=DiagnosticCommand");
        System.out.print(ManagementFactory.getPlatformMBeanServer()
                .invoke(commands, "compilerCodelist", null, null));
        System.out.flush();
        arm();
        outer(value);
    }
}
