run-android: build-android-library
	cargo apk run --manifest-path ./examples/android/Cargo.toml

build-android-library:
	cargo ndk -t arm64-v8a build

build-android: build-android-library
	cargo apk build --manifest-path ./examples/android/Cargo.toml

test-android: build-android
	./.github/workflows/android_test.sh ./examples/android/target/debug/apk/android.apk

test: test-ios test-android
	
test-android:
	cargo ndk -t arm64-v8a build
	(cd examples/android && cargo apk run)

test-ios:
	(cd examples/ios && cargo xcodebuild b && cargo xcodebuild o)
