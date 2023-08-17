/*
 * SPDX-FileCopyrightText: 2022-2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 * Based on BCR code.
 */

import com.google.protobuf.gradle.proto
import org.eclipse.jgit.api.ArchiveCommand
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.archive.TarFormat
import org.eclipse.jgit.lib.ObjectId
import org.jetbrains.kotlin.backend.common.pop
import org.json.JSONObject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.parcelize)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.protobuf)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

buildscript {
    dependencies {
        "classpath"(libs.jgit)
        "classpath"(libs.jgit.archive)
        "classpath"(libs.json)
    }
}

typealias VersionTriple = Triple<String?, Int, ObjectId>

fun describeVersion(git: Git): VersionTriple {
    // jgit doesn't provide a nice way to get strongly-typed objects from its `describe` command
    val describeStr = git.describe().setLong(true).call()

    return if (describeStr != null) {
        val pieces = describeStr.split('-').toMutableList()
        val commit = git.repository.resolve(pieces.pop().substring(1))
        val count = pieces.pop().toInt()
        val tag = pieces.joinToString("-")

        Triple(tag, count, commit)
    } else {
        val log = git.log().call().iterator()
        val head = log.next()
        var count = 1

        while (log.hasNext()) {
            log.next()
            ++count
        }

        Triple(null, count, head.id)
    }
}

fun getVersionCode(triple: VersionTriple): Int {
    val tag = triple.first
    val (major, minor) = if (tag != null) {
        if (!tag.startsWith('v')) {
            throw IllegalArgumentException("Tag does not begin with 'v': $tag")
        }

        val pieces = tag.substring(1).split('.')
        if (pieces.size != 2) {
            throw IllegalArgumentException("Tag is not in the form 'v<major>.<minor>': $tag")
        }

        Pair(pieces[0].toInt(), pieces[1].toInt())
    } else {
        Pair(0, 0)
    }

    // 8 bits for major version, 8 bits for minor version, and 8 bits for git commit count
    assert(major in 0 until 1.shl(8))
    assert(minor in 0 until 1.shl(8))
    assert(triple.second in 0 until 1.shl(8))

    return major.shl(16) or minor.shl(8) or triple.second
}

fun getVersionName(git: Git, triple: VersionTriple): String {
    val tag = triple.first?.replace(Regex("^v"), "") ?: "NONE"

    return buildString {
        append(tag)

        if (triple.second > 0) {
            append(".r")
            append(triple.second)

            append(".g")
            git.repository.newObjectReader().use {
                append(it.abbreviate(triple.third).name())
            }
        }
    }
}

val git = Git.open(File(rootDir, ".git"))!!
val gitVersionTriple = describeVersion(git)
val gitVersionCode = getVersionCode(gitVersionTriple)
val gitVersionName = getVersionName(git, gitVersionTriple)

val projectUrl = "https://github.com/chenxiaolong/Custota"
val releaseMetadataBranch = "master"

val extraDir = File(buildDir, "extra")
val archiveDir = File(extraDir, "archive")

android {
    namespace = "com.chiller3.custota"

    compileSdk = 33
    buildToolsVersion = "33.0.2"
    ndkVersion = "25.2.9519653"

    defaultConfig {
        applicationId = "com.chiller3.custota"
        minSdk = 33
        targetSdk = 33
        versionCode = gitVersionCode
        versionName = gitVersionName
        resourceConfigurations.addAll(listOf(
            "en",
            "vi",
        ))

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "PROJECT_URL_AT_COMMIT",
            "\"${projectUrl}/tree/${gitVersionTriple.third.name}\"")
    }
    sourceSets {
        getByName("main") {
            assets {
                srcDir(archiveDir)
            }
            proto {
                srcDir(File(rootDir, "protobuf"))
            }
        }
    }
    signingConfigs {
        create("release") {
            val keystore = System.getenv("RELEASE_KEYSTORE")
            storeFile = if (keystore != null) { File(keystore) } else { null }
            storePassword = System.getenv("RELEASE_KEYSTORE_PASSPHRASE")
            keyAlias = System.getenv("RELEASE_KEY_ALIAS")
            keyPassword = System.getenv("RELEASE_KEY_PASSPHRASE")
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")

            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility(JavaVersion.VERSION_17)
        targetCompatibility(JavaVersion.VERSION_17)
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
        }
    }
    buildFeatures {
        aidl = true
        buildConfig = true
        viewBinding = true
    }
    lint {
        // The translations are always going to lag behind new strings being
        // added to values/strings.xml
        disable += "MissingTranslation"
    }
}

protobuf {
    protoc {
        artifact = libs.protoc.get().toString()
    }

    generateProtoTasks {
        all().configureEach {
            builtins {
                create("java") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.activity)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.bouncycastle.pkix)
    implementation(libs.bouncycastle.prov)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.material)
    implementation(libs.protobuf.javalite)
}

val archive = tasks.register("archive") {
    inputs.property("gitVersionTriple.third", gitVersionTriple.third)

    val outputFile = File(archiveDir, "archive.tar")
    outputs.file(outputFile)

    doLast {
        val format = "tar_for_task_$name"

        ArchiveCommand.registerFormat(format, TarFormat())
        try {
            outputFile.outputStream().use {
                git.archive()
                    .setTree(git.repository.resolve(gitVersionTriple.third.name))
                    .setFormat(format)
                    .setOutputStream(it)
                    .call()
            }
        } finally {
            ArchiveCommand.unregisterFormat(format)
        }
    }
}

android.applicationVariants.all {
    val variant = this
    val capitalized = variant.name.replaceFirstChar { it.uppercase() }
    val variantDir = File(extraDir, variant.name)

    variant.preBuildProvider.configure {
        dependsOn(archive)
    }

    val moduleProp = tasks.register("moduleProp${capitalized}") {
        inputs.property("projectUrl", projectUrl)
        inputs.property("releaseMetadataBranch", releaseMetadataBranch)
        inputs.property("rootProject.name", rootProject.name)
        inputs.property("variant.applicationId", variant.applicationId)
        inputs.property("variant.name", variant.name)
        inputs.property("variant.versionCode", variant.versionCode)
        inputs.property("variant.versionName", variant.versionName)

        val outputFile = File(variantDir, "module.prop")
        outputs.file(outputFile)

        doLast {
            val props = LinkedHashMap<String, String>()
            props["id"] = variant.applicationId
            props["name"] = rootProject.name
            props["version"] = "v${variant.versionName}"
            props["versionCode"] = variant.versionCode.toString()
            props["author"] = "chenxiaolong"
            props["description"] = "Custom OTA updater"

            if (variant.name == "release") {
                props["updateJson"] = "${projectUrl}/raw/${releaseMetadataBranch}/app/module/updates/${variant.name}/info.json"
            }

            outputFile.writeText(props.map { "${it.key}=${it.value}" }.joinToString("\n"))
        }
    }

    val permissionsXml = tasks.register("permissionsXml${capitalized}") {
        inputs.property("variant.applicationId", variant.applicationId)

        val outputFile = File(variantDir, "privapp-permissions-${variant.applicationId}.xml")
        outputs.file(outputFile)

        doLast {
            outputFile.writeText("""
                <?xml version="1.0" encoding="utf-8"?>
                <permissions>
                    <privapp-permissions package="${variant.applicationId}">
                        <permission name="android.permission.ACCESS_CACHE_FILESYSTEM" />
                        <permission name="android.permission.MANAGE_CARRIER_OEM_UNLOCK_STATE" />
                        <permission name="android.permission.MANAGE_USER_OEM_UNLOCK_STATE" />
                        <permission name="android.permission.READ_OEM_UNLOCK_STATE" />
                        <permission name="android.permission.REBOOT" />
                    </privapp-permissions>
                </permissions>
            """.trimIndent())
        }
    }

    val configXml = tasks.register("configXml${capitalized}") {
        inputs.property("variant.applicationId", variant.applicationId)

        val outputFile = File(variantDir, "config-${variant.applicationId}.xml")
        outputs.file(outputFile)

        doLast {
            outputFile.writeText("""
                <?xml version="1.0" encoding="utf-8"?>
                <config>
                    <allow-in-power-save package="${variant.applicationId}" />
                    <hidden-api-whitelisted-app package="${variant.applicationId}" />
                </config>
            """.trimIndent())
        }
    }

    tasks.register<Zip>("zip${capitalized}") {
        inputs.property("rootProject.name", rootProject.name)
        inputs.property("variant.applicationId", variant.applicationId)
        inputs.property("variant.name", variant.name)
        inputs.property("variant.versionName", variant.versionName)

        archiveFileName.set("${rootProject.name}-${variant.versionName}-${variant.name}.zip")
        // Force instantiation of old value or else this will cause infinite recursion
        destinationDirectory.set(destinationDirectory.dir(variant.name).get())

        // Make the zip byte-for-byte reproducible (note that the APK is still not reproducible)
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true

        dependsOn.add(variant.assembleProvider)

        from(moduleProp.map { it.outputs })
        from(permissionsXml.map { it.outputs }) {
            into("system/etc/permissions")
        }
        from(configXml.map { it.outputs }) {
            into("system/etc/sysconfig")
        }
        from(variant.outputs.map { it.outputFile }) {
            into("system/priv-app/${variant.applicationId}")
        }

        val moduleDir = File(projectDir, "module")

        for (script in arrayOf("update-binary", "updater-script")) {
            from(File(moduleDir, script)) {
                into("META-INF/com/google/android")
            }
        }

        from(File(moduleDir, "boot_common.sh"))
        from(File(moduleDir, "customize.sh"))
        from(File(moduleDir, "post-fs-data.sh"))

        from(File(rootDir, "LICENSE"))
        from(File(rootDir, "README.md"))
    }

    tasks.register("updateJson${capitalized}") {
        inputs.property("gitVersionTriple.first", gitVersionTriple.first)
        inputs.property("projectUrl", projectUrl)
        inputs.property("rootProject.name", rootProject.name)
        inputs.property("variant.name", variant.name)
        inputs.property("variant.versionCode", variant.versionCode)
        inputs.property("variant.versionName", variant.versionName)

        val moduleDir = File(projectDir, "module")
        val updatesDir = File(moduleDir, "updates")
        val variantUpdateDir = File(updatesDir, variant.name)
        val jsonFile = File(variantUpdateDir, "info.json")

        outputs.file(jsonFile)

        doLast {
            if (gitVersionTriple.second != 0) {
                throw IllegalStateException("The release tag must be checked out")
            }

            val root = JSONObject()
            root.put("version", variant.versionName)
            root.put("versionCode", variant.versionCode)
            root.put("zipUrl", "${projectUrl}/releases/download/${gitVersionTriple.first}/${rootProject.name}-${variant.versionName}-release.zip")
            root.put("changelog", "${projectUrl}/raw/${gitVersionTriple.first}/app/module/updates/${variant.name}/changelog.txt")

            jsonFile.writer().use {
                root.write(it, 4, 0)
            }
        }
    }
}

data class LinkRef(val type: String, val number: Int, val user: String?) : Comparable<LinkRef> {
    override fun compareTo(other: LinkRef): Int = compareValuesBy(
        this,
        other,
        { it.type },
        { it.number },
        { it.user },
    )

    override fun toString(): String = buildString {
        append('[')
        append(type)
        append(" #")
        append(number)
        if (user != null) {
            append(" @")
            append(user)
        }
        append(']')
    }
}

fun checkBrackets(line: String) {
    var expectOpening = true

    for (c in line) {
        if (c == '[' || c == ']') {
            if (c == '[' != expectOpening) {
                throw IllegalArgumentException("Mismatched brackets: $line")
            }

            expectOpening = !expectOpening
        }
    }

    if (!expectOpening) {
        throw IllegalArgumentException("Missing closing bracket: $line")
    }
}

fun updateChangelogLinks(baseUrl: String) {
    val file = File(rootDir, "CHANGELOG.md")
    val regexStandaloneLink = Regex("\\[([^\\]]+)\\](?![\\(\\[])")
    val regexAutoLink = Regex("(Issue|PR) #(\\d+)(?: @([\\w-]+))?")
    val links = hashMapOf<LinkRef, String>()
    var skipRemaining = false
    val changelog = mutableListOf<String>()

    file.useLines { lines ->
        for (rawLine in lines) {
            val line = rawLine.trimEnd()

            if (!skipRemaining) {
                checkBrackets(line)
                val matches = regexStandaloneLink.findAll(line)

                for (linkMatch in matches) {
                    val linkText = linkMatch.groupValues[1]
                    val match = regexAutoLink.matchEntire(linkText)
                    require(match != null) { "Invalid link format: $linkText" }

                    val ref = match.groupValues[0]
                    val type = match.groupValues[1]
                    val number = match.groupValues[2].toInt()
                    val user = match.groups[3]?.value

                    val link = when (type) {
                        "Issue" -> {
                            require(user == null) { "$ref should not have a username" }
                            "$baseUrl/issues/$number"
                        }
                        "PR" -> {
                            require(user != null) { "$ref should have a username" }
                            "$baseUrl/pull/$number"
                        }
                        else -> throw IllegalArgumentException("Unknown link type: $type")
                    }

                    // #0 is used for examples only
                    if (number != 0) {
                        links[LinkRef(type, number, user)] = link
                    }
                }

                if ("Do not manually edit the lines below" in line) {
                    skipRemaining = true
                }

                changelog.add(line)
            }
        }
    }

    for ((ref, link) in links.entries.sortedBy { it.key }) {
        changelog.add("$ref: $link")
    }

    changelog.add("")

    file.writeText(changelog.joinToString("\n"))
}

fun updateChangelog(version: String?, replaceFirst: Boolean) {
    val file = File(rootDir, "CHANGELOG.md")
    val expected = if (version != null) { "### Version $version" } else { "### Unreleased" }

    val changelog = mutableListOf<String>().apply {
        // This preserves a trailing newline, unlike File.readLines()
        addAll(file.readText().lineSequence())
    }

    val index = changelog.indexOfFirst { it.startsWith("### ") }
    if (index == -1) {
        changelog.addAll(0, listOf(expected, ""))
    } else if (changelog[index] != expected) {
        if (replaceFirst) {
            changelog[index] = expected
        } else {
            changelog.addAll(index, listOf(expected, ""))
        }
    }

    file.writeText(changelog.joinToString("\n"))
}

fun updateModuleChangelog(gitRef: String) {
    File(File(File(File(projectDir, "module"), "updates"), "release"), "changelog.txt")
        .writeText("The changelog can be found at: [`CHANGELOG.md`]($projectUrl/blob/$gitRef/CHANGELOG.md).\n")
}

tasks.register("changelogUpdateLinks") {
    doLast {
        updateChangelogLinks(projectUrl)
    }
}

tasks.register("changelogPreRelease") {
    doLast {
        val version = project.property("releaseVersion")

        updateChangelog(version.toString(), true)
        updateModuleChangelog("v$version")
    }
}

tasks.register("changelogPostRelease") {
    doLast {
        updateChangelog(null, false)
        updateModuleChangelog(releaseMetadataBranch)
    }
}

tasks.register("preRelease") {
    dependsOn("changelogUpdateLinks")
    dependsOn("changelogPreRelease")
}

tasks.register("postRelease") {
    dependsOn("updateJsonRelease")
    dependsOn("changelogPostRelease")
}
