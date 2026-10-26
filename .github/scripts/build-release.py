#!/usr/bin/env python3
"""Build and verify local Linux release archives from a clean, pinned checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TAGS = "sing xray with_quic with_grpc with_utls with_wireguard with_acme with_gvisor"
BASE_ENV = {**os.environ, "GOWORK": "off", "GOEXPERIMENT": "jsonv2", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"}
TARGETS = [("amd64", "", "linux-64"), ("arm64", "", "linux-arm64-v8a"), ("arm", "7", "linux-arm32-v7a")]


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env or BASE_ENV, text=True).strip()


def digest(path, method="sha256"):
    result = hashlib.new(method)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def verify_buildinfo(binary, commit, pins):
    info = run("go", "version", "-m", str(binary))
    if f"vcs.revision={commit}" not in info or "vcs.modified=false" not in info:
        raise ValueError(f"{binary}: source revision is not the clean selected commit")
    for entry in pins:
        if entry["strategy"] == "replacement":
            expected = f'\t=>\t{entry["replacement"]}\t{entry["ref"]}\t'
            if expected not in info:
                raise ValueError(f"{binary}: missing exact remote fork {entry['replacement']}")
    if "GOEXPERIMENT=jsonv2" not in info or "CGO_ENABLED=0" not in info:
        raise ValueError(f"{binary}: incorrect build settings")
    return info


def build(binary, version, commit, pins, goos=None, goarch=None, goarm=None):
    env = dict(BASE_ENV)
    # Do not inherit a caller's cross-compilation target for the native check.
    for key in ("GOOS", "GOARCH", "GOARM"):
        env.pop(key, None)
    for key, value in (("GOOS", goos), ("GOARCH", goarch), ("GOARM", goarm)):
        if value:
            env[key] = value
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "go", "build", "-mod=readonly", "-trimpath", "-tags", TAGS,
        "-ldflags", f"-s -w -buildid= -X github.com/Designdocs/N2X/cmd.version={version}",
        "-o", str(binary), ".",
    ], cwd=ROOT, env=env, check=True)
    info = verify_buildinfo(binary, commit, pins)
    return {"path": str(binary), "sha256": digest(binary), "bytes": binary.stat().st_size, "buildinfo": info}


def archive(package, target, timestamp):
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(package.rglob("*")):
            if not path.is_file():
                continue
            info = zipfile.ZipInfo(path.relative_to(package).as_posix(), time.gmtime(timestamp)[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100755 if path.name == "N2X" else 0o100644) << 16
            with path.open("rb") as source, output.open(info, "w") as destination:
                shutil.copyfileobj(source, destination)
    with zipfile.ZipFile(target) as result:
        if result.testzip() is not None:
            raise ValueError(f"{target}: invalid ZIP CRC")
        config = json.loads(result.read("config.json"))
        if config.get("Memory") != {"SoftLimitPercent": 70, "RestartPercent": 90}:
            raise ValueError("release config lost the memory protection defaults")
    labels = [("md5", "MD5"), ("sha1", "SHA1"), ("sha256", "SHA2-256"), ("sha512", "SHA2-512")]
    checksum = target.with_suffix(target.suffix + ".dgst")
    checksum.write_text("".join(f"{label}= {digest(target, method)}\n" for method, label in labels))
    return [{"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)} for path in (target, checksum)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--geodata-dir", type=Path, default=ROOT / "example")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", args.version):
        parser.error("version must be an exact vMAJOR.MINOR.PATCH version")
    if run("git", "status", "--porcelain=v1"):
        raise ValueError("commit the source changes before building release archives")
    commit = run("git", "rev-parse", "HEAD")
    output = (args.output or ROOT / "output" / "releases" / args.version).resolve()
    marker = output / ".build-source.json"
    identity = {"version": args.version, "commit": commit}
    if output.exists() and any(output.iterdir()):
        if not marker.exists() or json.loads(marker.read_text()) != identity:
            raise ValueError(f"{output}: belongs to another build; choose a new output directory")
    output.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(identity, indent=2) + "\n")
    geodata = args.geodata_dir.resolve()
    data_files = {}
    for name in ("geoip.dat", "geosite.dat"):
        path = geodata / name
        if path.stat().st_size < 1024 * 1024:
            raise ValueError(f"{path}: invalid geodata payload")
        data_files[name] = {"sha256": digest(path), "bytes": path.stat().st_size}
    data_source = json.loads((geodata / "source.json").read_text()) if (geodata / "source.json").exists() else {"kind": "tracked example data", "commit": commit}
    if "files" in data_source:
        for name, expected in data_source["files"].items():
            if data_files[name]["sha256"] != expected["sha256"]:
                raise ValueError(f"{name}: changed since source verification")
    subprocess.run(["python3", ".github/scripts/sync-upstreams.py"], cwd=ROOT, env=BASE_ENV, check=True)
    subprocess.run(["go", "mod", "verify"], cwd=ROOT, env=BASE_ENV, check=True)
    pins = json.loads((ROOT / "UPSTREAMS.json").read_text())["entries"]
    tracked_examples = run("git", "ls-files", "--", "example/*.json").splitlines()
    docs = run("git", "ls-files", "--", "docs/*.md").splitlines()
    timestamp = int(run("git", "show", "-s", "--format=%ct", "HEAD"))
    binaries, assets = [], []
    for arch, arm, target in TARGETS:
        print(f"Building {target} from {commit}", flush=True)
        package = output / target
        binary = package / "N2X"
        entry = build(binary, args.version, commit, pins, "linux", arch, arm)
        entry.update({"target": target, "goarch": arch, "goarm": arm})
        (output / (target + ".buildinfo.txt")).write_text(entry.pop("buildinfo") + "\n")
        binaries.append(entry)
        for name in ("LICENSE", "README.md"):
            shutil.copy2(ROOT / name, package / name)
        for name in tracked_examples:
            shutil.copy2(ROOT / name, package / Path(name).name)
        for name in docs:
            destination = package / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        for name in data_files:
            shutil.copy2(geodata / name, package / name)
        assets.extend(archive(package, output / f"N2X-{target}.zip", timestamp))
    native = output / "validation" / "native" / "N2X"
    native_info = build(native, args.version, commit, pins)
    version = run(str(native), "version")
    if f"N2X {args.version} " not in version or "Supported cores: sing, xray" not in version:
        raise ValueError("native binary reports an incorrect version or missing core")
    (output / "native.buildinfo.txt").write_text(native_info.pop("buildinfo") + "\n")
    (output / "native-version.txt").write_text(version + "\n")
    manifest = {
        **identity, "toolchain": run("go", "version"), "tags": TAGS, "workspace": "off",
        "core_pins": pins, "geodata": {"source": data_source, "files": data_files},
        "binaries": binaries, "native_validation": native_info, "assets": assets,
        "git_tag_created": False, "release_published": False,
    }
    (output / "release-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"Verified {len(assets)} release assets in {output}", flush=True)


if __name__ == "__main__":
    main()
