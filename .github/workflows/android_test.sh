#!/bin/bash

set -e

adb uninstall id.animo.example.android || true
adb install -r "$1"
adb shell am start -a android.intent.action.MAIN -n "id.animo.example.android/android.app.NativeActivity"

sleep 10

LOG=$(adb logcat -d RustStdoutStderr:D '*:S')

if echo $LOG | grep 'RustStdoutStderr';
then
    echo "App running"
    MSG=$(echo $LOG | grep 'panicked')
    echo $MSG
    if [ -z "$MSG" ]; then
      echo "::success:: All tests passed!"
      exit 0
    else
      echo "::error:: Rust panicked! Tests failed. Logs will be uploaded"
      echo $LOG >> ~/logcat.log
      exit 1
    fi
else
    echo "::error:: App not running"
    exit 1
fi

