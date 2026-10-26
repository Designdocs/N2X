#!/usr/bin/env python3
"""Apply exact reviewed module pins without replacing N2X's fork extensions."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ENV = {**os.environ, "GOWORK": "off", "GOEXPERIMENT": "jsonv2", "GOTOOLCHAIN": "local"}


def go(*args):
    return subprocess.check_output(["go", *args], cwd=ROOT, env=ENV, text=True)


def entries():
    manifest = json.loads((ROOT / "UPSTREAMS.json").read_text())
    if manifest.get("version") != 2:
        raise ValueError("UPSTREAMS.json must use version 2")
    result = manifest["entries"]
    seen = set()
    for entry in result:
        module, ref, strategy = (entry[key] for key in ("module", "ref", "strategy"))
        if module in seen:
            raise ValueError(f"duplicate module {module}")
        seen.add(module)
        if not re.fullmatch(r"v\d+\.\d+\.\d+[0-9A-Za-z.+-]*", ref):
            raise ValueError(f"{module}: require an exact version, not latest or a branch")
        if strategy not in {"replacement", "version"}:
            raise ValueError(f"{module}: unsupported strategy {strategy}")
        if strategy == "replacement" and not entry.get("replacement"):
            raise ValueError(f"{module}: missing fork replacement")
    return result


def check(pins):
    selected = go("list", "-mod=readonly", "-m", "-json", *(pin["module"] for pin in pins))
    decoder, modules = json.JSONDecoder(), {}
    while selected.strip():
        item, offset = decoder.raw_decode(selected.lstrip())
        modules[item["Path"]] = item
        selected = selected.lstrip()[offset:]
    for pin in pins:
        module = pin["module"]
        actual = modules[module]
        if pin["strategy"] == "replacement":
            replacement = actual.get("Replace", {})
            expected = (pin["replacement"], pin["ref"])
            observed = (replacement.get("Path"), replacement.get("Version"))
        else:
            if "Replace" in actual:
                raise ValueError(f"{module}: unexpected replacement bypasses the reviewed version")
            expected, observed = (module, pin["ref"]), (module, actual.get("Version"))
        if observed != expected:
            raise ValueError(f"{module}: selected {observed}, expected {expected}")
        print(f"Verified {module} => {expected[0]}@{expected[1]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply reviewed pins and tidy before checking")
    args = parser.parse_args()
    pins = entries()
    if args.apply:
        # Edit all reviewed versions together, then resolve one dependency graph.
        # Never run go get against the unmodified upstream core repositories.
        edits = []
        for pin in pins:
            if pin["strategy"] == "replacement":
                edits.append(f'-replace={pin["module"]}={pin["replacement"]}@{pin["ref"]}')
            else:
                edits.append(f'-require={pin["module"]}@{pin["ref"]}')
        go("mod", "edit", *edits)
        go("mod", "tidy")
    check(pins)


if __name__ == "__main__":
    main()
