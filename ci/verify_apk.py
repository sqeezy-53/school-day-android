#!/usr/bin/env python3
"""Verify Android APK identity, ABI set and signing certificate."""
import argparse
from pathlib import Path
import re
from struct import Struct
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

def verify_library(binary, name):
    header = Struct("<16sHHIQQQIHHHHHH")
    segment = Struct("<IIQQQQQQ")
    if len(binary) < header.size or not binary.startswith(b"\x7fELF\x02\x01"):
        raise ValueError(f"Invalid 64-bit ELF library: {name}")
    fields = header.unpack_from(binary)
    offset, entry_size, count = fields[5], fields[9], fields[10]
    if entry_size != segment.size or offset < header.size or offset + entry_size * count > len(binary):
        raise ValueError(f"Invalid ELF program headers: {name}")
    loads = [
        row for i in range(count)
        if (row := segment.unpack_from(binary, offset + i * entry_size))[0] == 1
    ]
    if not loads or any(row[7] < 16384 or (row[2] - row[3]) % 16384 for row in loads):
        raise ValueError(f"ELF LOAD segments are not aligned for 16 KB pages: {name}")


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
        libraries = [name for name in apk.namelist() if
                     len(parts := name.split("/")) == 3 and parts[0] == "lib" and parts[2].endswith(".so")]
        abis = {name.split("/")[1] for name in libraries}
        if abis != ABIS or any(f"lib/{abi}/libschool_day_android.so" not in libraries for abi in ABIS):
            raise ValueError("APK does not contain the required JNI ABIs")
        for library in libraries:
            verify_library(apk.read(library), library)
    subprocess.run([args.tools / "zipalign", "-c", "-P", "16", "4", args.apk], check=True)
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
