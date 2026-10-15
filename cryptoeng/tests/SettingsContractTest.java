import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

// Loads the UNMODIFIED on-device Settings APK via app_process CLASSPATH.
// No Binder calls, account access or production credential reads.
public final class SettingsContractTest {
    static Object call(Object obj, String method) throws Exception {
        Method m = obj.getClass().getDeclaredMethod(method);
        m.setAccessible(true);
        return m.invoke(obj);
    }
    static boolean accepts(byte[] reply) throws Exception {
        Class<?> parser = Class.forName("com.oplus.settings.privacy.sdk.RpmbResultParser");
        Method parse = parser.getDeclaredMethod("parse", byte[].class);
        parse.setAccessible(true);
        Object summary = parse.invoke(null, (Object)reply);
        if (summary == null || !(Boolean)call(summary, "isExeSuccess")) return false;
        Object command = call(summary, "getMethodType");
        if ((Integer)call(command, "getCode") != 4002) return false;
        Class<?> type = Class.forName("com.oplus.settings.privacy.sdk.MethodParamType");
        Method get = type.getDeclaredMethod("get", int.class); get.setAccessible(true);
        Object challengeType = get.invoke(null, 206);
        Method param = summary.getClass().getDeclaredMethod("getResultParam", type);
        param.setAccessible(true);
        Object value = param.invoke(summary, challengeType);
        if (value == null) return false;
        byte[] challenge = (byte[])call(value, "getBuffer");
        return challenge != null && challenge.length == 64;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !args[0].startsWith("/data/local/tmp/cryptoeng-contract."))
            throw new IllegalArgumentException("synthetic fixture directory required");
        for (String file : new String[]{"verify-good.bin", "verify-bad.bin", "verify-new.bin"}) {
            boolean actual = accepts(Files.readAllBytes(Paths.get(args[0], file)));
            boolean expected = !file.equals("verify-bad.bin");
            if (actual != expected) throw new AssertionError(file);
            System.out.println("PASS actual Settings RpmbResultParser: " + file + " accepted=" + actual);
        }
    }
}
