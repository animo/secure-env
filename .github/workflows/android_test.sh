#!/bin/bash

set -e

adb uninstall id.animo.example.android || true
adb install -r "$1"
adb shell am start -a android.intent.action.MAIN -n "id.animo.example.android/android.app.NativeActivity"

sleep 30

adb logcat RustStdoutStderr:D '*:S' | tee ~/logcat.log

if grep 'RustStdoutStderr' ~/logcat.log;
then
    echo "App running"
else
    echo "::error:: App not running"
    exit 1
fi

MSG=$(grep -e 'panicked' "$HOME"/logcat.log)
if [ -z "${MSG}" ]; then
  echo "::error:: Rust panicked! Tests failed. Logs will be uploaded"
  exit 1
else
  exit 0
fi
