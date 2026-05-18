"""Shared helpers for the APK analyzer tests.

Builds a tiny synthetic APK (really just a ZIP with the right files
inside) and returns its raw bytes. The bytes are served by a
respx-mocked download URL so the tool's ``_scan_apk`` regex picks up a
known set of planted strings.

This file is named ``conftest.py`` to keep the synthetic-APK helper
co-located with the APKMirror HTML fixtures, but it is loaded by an
explicit import from the test module (the directory is not on
pytest's collection path, so the file does not contribute pytest
fixtures via the usual auto-discovery mechanism).

The planted secrets are:

* ``AKIAIOSFODNN7EXAMPLE`` — matches the ``aws_access_key`` regex.
* ``https://api.example.com/v1/users`` — matches the generic
  ``https?://...`` endpoint regex.
* ``android.permission.INTERNET`` — surfaces in the manifest
  permission scan.
"""
from __future__ import annotations

import io
import zipfile


def build_synthetic_apk() -> bytes:
    """Return the bytes of a synthetic APK with planted secrets."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # AndroidManifest.xml as plain XML. Real APKs use binary AXML,
        # but the scanner does a utf-8 decode + regex sweep — plain XML
        # is fine for the test.
        z.writestr(
            "AndroidManifest.xml",
            (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
                '          package="com.example.app"\n'
                '          android:versionName="1.2.3">\n'
                '  <uses-permission android:name="android.permission.INTERNET"/>\n'
                '  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>\n'
                "</manifest>\n"
            ),
        )
        # A planted .smali file with an AWS key and an HTTPS endpoint.
        z.writestr(
            "smali/com/example/app/Config.smali",
            (
                ".class public Lcom/example/app/Config;\n"
                ".super Ljava/lang/Object;\n\n"
                '.field public static final AWS_KEY:Ljava/lang/String; = "AKIAIOSFODNN7EXAMPLE"\n'
                '.field public static final API_URL:Ljava/lang/String; = "https://api.example.com/v1/users"\n'
                '.field public static final DB_PW:Ljava/lang/String; = "password123"\n'
            ),
        )
        # A strings.xml so the .xml branch also fires.
        z.writestr(
            "res/values/strings.xml",
            (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                "<resources>\n"
                '  <string name="api_base">https://api.example.com/v1/users</string>\n'
                "</resources>\n"
            ),
        )
        # A placeholder native lib so third_party_libs gets populated.
        z.writestr("lib/arm64-v8a/libexample.so", b"\x7fELF" + b"\x00" * 60)
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()
