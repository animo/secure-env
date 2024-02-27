#!/bin/bash

adb uninstall id.animo.example.android || true
adb install -r "$1"
adb logcat -c
adb shell am start -a android.intent.action.MAIN -n "id.animo.example.android/android.app.NativeActivity"

sleep  10

LOG=$(adb logcat -d RustStdoutStderr:D '*:S')
HAS_STARTED=$(echo $LOG | grep 'RustStdoutStderr')
HAS_ERROR=$(echo $LOG | grep 'panicked')

if [ -n "$HAS_STARTED" ]; then
    echo "App running"
else
    echo "::error:: App not running"
    exit 1
fi

if [ -n "$HAS_ERROR" ]; then
  cat $LOG
  echo "::error:: Rust panicked! Tests failed. Logs will be uploaded"
  exit 1
else
  echo "::success:: All tests passed!"
  exit 0
fi

exit 0
