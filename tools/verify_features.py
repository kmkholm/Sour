# -*- coding: utf-8 -*-
"""Feature parity check: training-side extractor vs the C# engine, on real local PE files.

For each file:   thrember (pefile) raw features -> ml/featspec.features_from_json
is compared with Sour.exe --features (src/Sour/Av/PeFeatures.cs).
A model is only as good as the agreement between these two paths.

usage: python tools/verify_features.py [n_files]
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ml"))
from featspec import FEATURE_NAMES, features_from_json  # noqa: E402
import thrember  # noqa: E402
from thrember.features import PEFeatureExtractor  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 150
EXE = os.path.join(HERE, "..", "bin", "Sour.exe")
ROOTS = [r"C:\Windows\System32", r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Windows\SysWOW64",
         r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319", os.path.expandvars(r"%LOCALAPPDATA%\Programs")]


def pick():
    files = []
    per_root = max(N // len(ROOTS), 5)
    for root in ROOTS:
        got = 0
        for dp, dn, fn in os.walk(root):
            dn[:] = dn[:25]
            for f in fn[:40:7]:   # few per folder -> many different vendors/compilers
                if f.lower().endswith((".exe", ".dll", ".sys", ".ocx")):
                    p = os.path.join(dp, f)
                    try:
                        if 2048 < os.path.getsize(p) < 30 * 1024 * 1024:
                            files.append(p); got += 1
                    except OSError:
                        pass
                if got >= per_root:
                    break
            if got >= per_root:
                break
    return files[:N]


def main():
    files = pick()
    ext = PEFeatureExtractor()
    ref = {}
    for f in files:
        try:
            raw = ext.raw_features(open(f, "rb").read())
            if raw.get("general", {}).get("is_pe"):
                ref[f] = features_from_json(raw)
        except Exception as e:
            print("skip", f, type(e).__name__, e)
    files = list(ref)
    got = {}
    for i in range(0, len(files), 25):
        out = subprocess.run([EXE, "--features"] + files[i:i + 25], capture_output=True, text=True, encoding="utf-8").stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                d = json.loads(line)
                if d["valid"]:
                    got[d["file"]] = d["x"]
    bad_feat = {}
    exact = 0
    worst = []
    for f in files:
        if f not in got:
            print("C# did not parse:", f); continue
        diffs = []
        for name, a, b in zip(FEATURE_NAMES, ref[f], got[f]):
            if abs(a - b) > 1e-6 * max(1.0, abs(a)):
                diffs.append((name, a, b))
                bad_feat[name] = bad_feat.get(name, 0) + 1
        if not diffs:
            exact += 1
        else:
            worst.append((len(diffs), f, diffs[:4]))
    print(f"files compared: {len(files)}   identical vectors: {exact}   ({100.0 * exact / max(len(files), 1):.1f}%)")
    for name, c in sorted(bad_feat.items(), key=lambda kv: -kv[1]):
        print(f"  mismatch {name}: {c} files")
    for n, f, d in sorted(worst, reverse=True)[:8]:
        print(f"  {n} diffs  {f}")
        for name, a, b in d:
            print(f"       {name}: python={a:.6g} csharp={b:.6g}")
    return 0 if exact == len(files) else 1


if __name__ == "__main__":
    sys.exit(main())
