/*
 *  Copyright (c) 2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import com.github.jk1.license.filter.ExcludeTransitiveDependenciesFilter
import com.github.jk1.license.filter.LicenseBundleNormalizer
import com.github.jk1.license.filter.ReduceDuplicateLicensesFilter
import com.github.jk1.license.render.InventoryMarkdownReportRenderer


plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("kotlin-kapt")
    id("kotlin-parcelize")
    alias(libs.plugins.dokka)
    alias(libs.plugins.dependency.license.report)
    alias(libs.plugins.dependencycheck)
    alias(libs.plugins.sonarqube)
    alias(libs.plugins.maven.publish)
}

apply(from = "jacoco.gradle")
apply(plugin = "maven-publish")

val NAMESPACE: String by project
val GROUP: String by project
val POM_DESCRIPTION: String by project
val POM_SCM_URL: String by project

android {
    namespace = NAMESPACE
    group = GROUP
    compileSdk = 33

    defaultConfig {
        minSdk = 26
        targetSdk = 33

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testApplicationId = "eu.europa.ec.eudi.wallet.test"
        testHandleProfiling = true
        testFunctionalTest = true
        testOptions {
            // Override the placeholders for unit tests
            manifestPlaceholders["openid4vciAuthorizeHost"] = "authorize"
            manifestPlaceholders["openid4vciAuthorizePath"] = ""
            manifestPlaceholders["openid4vciAuthorizeScheme"] = "eudi-openid4ci"
        }

        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        getByName("debug") {
            isTestCoverageEnabled = true
        }

        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
        targetCompatibility = JavaVersion.toVersion(libs.versions.java.get())
    }
    kotlinOptions {
        jvmTarget = libs.versions.java.get()
    }

    sourceSets {
        getByName("test") {
            resources.srcDirs("src\\test\\assets")
        }
    }

//    publishing {
//        singleVariant('release') {
//            withSourcesJar()
//            // TODO fix javadoc in release
//            //  task javaDocReleaseGeneration fails with java.lang.UnsupportedOperationException: PermittedSubclasses requires ASM9
//            //  caused by eu.europa.ec.eudi.openid4vp.ResolvedRequestObject which is a sealed interface
////            withJavadocJar()
//        }
//    }
}

dependencies {

    implementation(libs.appcompat)

    // EUDI libs
    api(libs.eudi.document.manager)
    api(libs.eudi.iso18013.data.transfer)

    // OpenID4VCI
    implementation(libs.eudi.lib.jvm.openid4vci.kt)
    implementation(libs.nimbus.oauth2.oidc.sdk)

    // Siop-Openid4VP library
    implementation (libs.eudi.lib.jvm.siop.openid4vp.kt) {
        exclude(group = "org.bouncycastle")
    }

    // Google library
    implementation (libs.identity.credential) {
        exclude(group = "org.bouncycastle")
    }
    implementation (libs.android.identity.credential) {
        exclude(group = "org.bouncycastle")
    }

    // CBOR
    implementation(libs.cbor)

    implementation(libs.biometric.ktx)

    // Ktor Android Engine
    runtimeOnly(libs.ktor.client.android)

    // Bouncy Castle
    implementation(libs.bouncy.castle.prov)
    implementation(libs.bouncy.castle.pkix)

    implementation(libs.upokecenter.cbor)
    implementation(libs.cose.java)

    testImplementation(libs.junit)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.json)
    testImplementation(libs.mockk)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.identity.credential)
    testImplementation(libs.android.identity.credential)

    androidTestImplementation(libs.android.junit)
    androidTestImplementation(libs.mockito.android)
    androidTestImplementation(libs.test.core)
    androidTestImplementation(libs.test.runner)
    androidTestImplementation(libs.test.rules)
    androidTestImplementation(libs.test.coreKtx)
    androidTestImplementation(libs.espresso.core)
    androidTestImplementation(libs.espresso.contrib)
    androidTestImplementation(libs.espresso.intents)
}

dependencyCheck {

    val nvdApiKey: String? = System.getenv("NVD_API_KEY")
    formats = listOf("XML", "HTML")

    nvdApiKey?.let {
        nvd.apiKey = it
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.register<Delete>("clearDocsDir") {
    delete(file("$rootDir/docs"))
}

tasks.dokkaGfm {
    dependsOn("clearDocsDir")
    outputDirectory.set(file("$rootDir/docs"))
}

licenseReport {
    unionParentPomLicenses = false
    filters = arrayOf(
        LicenseBundleNormalizer(),
        ReduceDuplicateLicensesFilter(),
        ExcludeTransitiveDependenciesFilter()
    )
    configurations = arrayOf("releaseRuntimeClasspath")
    excludeBoms = true
    excludeOwnGroup = true
    renderers = arrayOf(
        InventoryMarkdownReportRenderer("licenses.md", POM_DESCRIPTION)
    )
}

tasks.register<Copy>("copyLicenseReport") {
    from("$buildDir/reports/dependency-license/licenses.md")
    into("$rootDir")
    dependsOn("generateLicenseReport")
}

tasks.named("generateLicenseReport") {
    finalizedBy("copyLicenseReport")
}

tasks.named("build") {
    finalizedBy("generateLicenseReport", "dokkaGfm")
}

tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.dokkaHtml)
    from(tasks.dokkaHtml.get().outputDirectory)
    archiveClassifier.set("html-docs")
}

tasks.register<Jar>("dokkaJavadocJar") {
    dependsOn(tasks.dokkaJavadoc)
    from(tasks.dokkaJavadoc.get().outputDirectory)
    archiveClassifier.set("javadoc")
}

mavenPublishing {
    pom {
        ciManagement {
            system.set("github")
            url.set("$POM_SCM_URL/actions")
        }
    }
}

afterEvaluate {
    tasks.named("javaDocReleaseGeneration").configure {
        enabled = false
    }

    publishing {
        publications {
            create<MavenPublication>("eudi-lib-android-wallet-core") {
                groupId = "com.github.TICESoftware"
                artifactId = "eudi-lib-android-wallet-core"
                version = "0.0.1"

                afterEvaluate {
                    from(components["release"])
                }
            }
        }
    }
}