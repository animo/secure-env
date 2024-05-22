run-android: build-android-library
	cargo apk run --manifest-path ./examples/android/Cargo.toml

build-android-library:
	cargo ndk -t arm64-v8a build --features=android_testing

build-android: build-android-library
	cargo apk build --manifest-path ./examples/android/Cargo.toml

test: test-ios test-android
	
test-android:
	cargo ndk -t arm64-v8a build --features=android_testing
	(cd examples/android && cargo apk run)

test-ios:
	(cd examples/ios && cargo xcodebuild b && cargo xcodebuild o)
