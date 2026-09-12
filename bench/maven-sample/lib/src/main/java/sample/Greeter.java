package sample;

/** The leaf module: something real to compile and depend on. */
public final class Greeter {
    private Greeter() {}

    public static String greet(String name) {
        return "hello, " + name;
    }
}
