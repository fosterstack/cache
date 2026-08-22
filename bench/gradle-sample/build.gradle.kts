// Deliberately not a "hello world" — a handful of real modules with real
// (if small) compilation work and a real inter-module dependency graph,
// so a cache hit is measuring something (recompiling 4 modules' worth of
// Java sources) rather than an empty task that would cache-hit trivially
// either way. This is the project addendum's build-scope item "benchmarks
// against a real Gradle project" runs against — see
// .github/workflows/benchmark.yml.
subprojects {
    plugins.apply("java")

    group = "com.fosterstack.bench"
    version = "1.0.0"

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    repositories {
        mavenCentral()
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
