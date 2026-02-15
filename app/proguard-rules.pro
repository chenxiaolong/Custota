# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.kts.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Keep log tags.
-keepclasseswithmembers,allowoptimization,allowshrinking class com.chiller3.custota.** {
    static final java.lang.String TAG;
}

# We construct TreeDocumentFile via reflection in DocumentFileExtensions
# to speed up SAF performance when doing path lookups.
-keepclassmembers class androidx.documentfile.provider.TreeDocumentFile {
    <init>(androidx.documentfile.provider.DocumentFile, android.content.Context, android.net.Uri);
}

# Keep classes generated from AIDL
-keep class android.os.IUpdateEngine* {
    *;
}
-keep class android.os.IUpdateEngineCallback* {
    *;
}
-keep class android.service.oemlock.IOemLockService* {
    *;
}

# Keep classes generated from protobuf
-keep class android.ota.OtaPackageMetadata* {
    *;
}

# Keep standalone CLI utilities
-keep class com.chiller3.custota.standalone.* {
    void main(java.lang.String[]);
}

# These exception classes have no source-level differences, but are absolutely different
# semantically. r8 wants to deduplicate them, which is just wrong.
-keep class com.chiller3.custota.updater.UpdaterThread$*Exception {
    *;
}
