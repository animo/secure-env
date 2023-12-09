run-android: build-android
	cargo apk run --example=android

build-android:
	cargo ndk -t arm64-v8a build
