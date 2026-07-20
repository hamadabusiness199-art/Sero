plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.bander.sero"
<<<<<<< HEAD
    compileSdk = 36
=======
    compileSdk = flutter.compileSdkVersion
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.bander.sero"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        // Locked to API 30+ so KeyGenParameterSpec.Builder.setMgf1Digests(SHA-256) is
        // available, which is required for the Android Keystore to produce RSA-OAEP
        // ciphertexts using MGF1-SHA256 (byte-compatible with the Python/iOS side).
        minSdk = maxOf(flutter.minSdkVersion, 30)
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
<<<<<<< HEAD
dependencies {
    implementation("org.signal:aesgcmprovider:0.0.3")
}
=======
>>>>>>> dc73e19c0a1ff98a8b3c8cf8e378318f197e1a59
