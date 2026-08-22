rootProject.name = "fscache-bench"

include("core", "module-a", "module-b", "module-c")

// The FosterStack Cache URL is injected via -PcacheUrl (or the
// FSCACHE_BENCH_URL env var) by the benchmark workflow — see
// .github/workflows/benchmark.yml. With neither set, the build cache is
// simply not configured and this project behaves like any ordinary
// Gradle project (local build-cache only), so it's also a normal,
// runnable sample outside the benchmark.
val cacheUrl: String? = (providers.gradleProperty("cacheUrl").orNull
    ?: providers.environmentVariable("FSCACHE_BENCH_URL").orNull)

if (cacheUrl != null) {
    buildCache {
        local {
            isEnabled = false // force every hit through the remote FosterStack Cache
        }
        remote<HttpBuildCache> {
            url = uri(cacheUrl)
            isPush = true
            isAllowInsecureProtocol = true // benchmark runs against plain http://localhost
        }
    }
}
