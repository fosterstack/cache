dependencies {
    // core is a direct dependency too, not just transitive through a/b —
    // the plain `java` plugin's `implementation` configuration doesn't
    // leak to consumers' compile classpath (that's `java-library`'s
    // `api`), and Checkout.java uses core types directly.
    implementation(project(":core"))
    implementation(project(":module-a"))
    implementation(project(":module-b"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
