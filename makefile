run-android: build-android-library
	cargo apk run --manifest-path ./examples/android/Cargo.toml

build-android-library:
	cargo ndk -t arm64-v8a build

build-android: build-android-library
	cargo apk build --manifest-path ./examples/android/Cargo.toml

test-android: build-android
	./.github/workflows/android_test.sh ./examples/android/target/debug/apk/android.apk
