import java.lang.management.ManagementFactory;
import javax.management.ObjectName;

public class HotspotWorkload {
    static volatile long value;

    static long work(long x) { return x * 31 + 1; }
    static long leaf(long x) { return work(x) + work(x + 1); }
    static long middle(long x) { return leaf(x) + leaf(x + 1); }
    static long outer(long x) { return middle(x) + middle(x + 1); }
    static long driver(long x) { return outer(x) + 1; }

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 200_000; i++) value = driver(value);
        var commands = new ObjectName("com.sun.management:type=DiagnosticCommand");
        System.out.print(ManagementFactory.getPlatformMBeanServer()
                .invoke(commands, "compilerCodelist", null, null));
        System.out.println("READY");
        for (;;) value = driver(value);
    }
}
