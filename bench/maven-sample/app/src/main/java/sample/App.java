package sample;

/** Depends on lib, so the module graph has a real edge. */
public final class App {
    private App() {}

    public static String run() {
        return Greeter.greet("cache");
    }
}
