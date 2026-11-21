#!/usr/bin/env python3
"""Verify Android APK identity, ABI set and signing certificate."""
import argparse
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile

PACKAGE = "io.github.sqeezy53.schoolday"
ABIS = {"arm64-v8a", "x86_64"}

def version_code(version):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("A stable numeric version is required")
    major, minor, patch = map(int, version.split("."))
    code = major * 1_000_000 + minor * 1_000 + patch
    if minor >= 1000 or patch >= 1000 or not 0 < code <= 2_100_000_000:
        raise ValueError("Version cannot be represented without a versionCode collision")
    return str(code)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--signature", choices=("unsigned", "debug", "release"), required=True)
    parser.add_argument("--certificate", default="")
    args = parser.parse_args()
    identity = subprocess.check_output([args.tools / "aapt", "dump", "badging", args.apk], text=True)
    match = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", identity, re.M)
    if not match or match.groups() != (PACKAGE, version_code(args.version), args.version):
        raise ValueError("Unexpected Android package or version")
    if ("application-debuggable" in identity.splitlines()) != (args.signature == "debug"):
        raise ValueError("Unexpected Android debuggable flag")
    with ZipFile(args.apk) as apk:
        abis = {parts[1] for name in apk.namelist() if
                len(parts := name.split("/")) == 3 and parts[0] == "lib" and parts[2].endswith(".so")}
        if abis != ABIS or any(f"lib/{abi}/libschool_day_android.so" not in apk.namelist() for abi in ABIS):
            raise ValueError("APK does not contain the required JNI ABIs")
    if args.signature != "unsigned":
        check = subprocess.check_output([args.tools / "apksigner", "verify", "--print-certs", args.apk], text=True)
        certs = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]{64})$", check, re.M)
        if len(certs) != 1:
            raise ValueError("Expected exactly one APK signer")
        if args.signature == "release":
            expected = args.certificate.replace(":", "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or certs[0].lower() != expected:
                raise ValueError("Release signing certificate did not match the configured fingerprint")
        print(f"Certificate SHA-256 {certs[0].lower()}")
    print(f"{PACKAGE} {args.version} {version_code(args.version)} {', '.join(sorted(abis))}")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
