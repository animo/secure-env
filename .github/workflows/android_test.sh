#!/bin/bash

set -e

adb uninstall id.animo.example.android || true
adb install -r "$1"
adb shell am start -a android.intent.action.MAIN -n "id.animo.example.android/android.app.NativeActivity"

sleep 30

adb logcat *:E android:V -d | tee ~/logcat.log

if grep 'android' ~/logcat.log;
then
    echo "App running"
else
    echo "::error:: App not running"
    exit 1
fi

MSG=$(grep -e 'RustPanic' "$HOME"/logcat.log)
if [ -z "${MSG}" ]; then
  exit 0
else
  echo "::error:: Rust panicked! Tests failed. Logs will be uploaded"
  exit 1
fi
