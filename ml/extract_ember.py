# -*- coding: utf-8 -*-
"""Stream EMBER2024 raw JSONL (inside the zip archives) into Sour feature matrices.

CPU only, single process, below-normal priority. Reads the first CAP records of
every weekly file, so each calendar week contributes equally; the cap is stated
in ml/model_card.json (no silent caps).

usage: python extract_ember.py <ember_raw_dir> <out_dir> [cap_per_week]
"""
import ctypes
import json
import os
import sys
import time
import zipfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from featspec import N_FEATURES, features_from_json  # noqa: E402

try:
    import orjson
    loads = orjson.loads
except ImportError:
    loads = json.loads


def main():
    raw, out = sys.argv[1], sys.argv[2]
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 2500
    os.makedirs(out, exist_ok=True)
    try:  # BELOW_NORMAL_PRIORITY_CLASS
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x4000)
    except Exception:
        pass
    log = open(os.path.join(out, "extract_log.txt"), "a", encoding="utf-8")

    def say(msg):
        line = time.strftime("%H:%M:%S ") + msg
        print(line, flush=True)
        log.write(line + "\n")
        log.flush()

    for split in ("test", "train"):
        done_flag = os.path.join(out, f"{split}_X.npy")
        if os.path.exists(done_flag):
            say(f"{split}: already extracted, skipping")
            continue
        X, y, meta = [], [], []
        bad = 0
        for ftype in ("Win32", "Win64", "Dot_Net"):
            zp = os.path.join(raw, f"{ftype}_{split}.zip")
            if not os.path.exists(zp):
                say(f"missing {zp}")
                continue
            z = zipfile.ZipFile(zp)
            for member in sorted(n for n in z.namelist() if n.endswith(".jsonl")):
                k = 0
                with z.open(member) as fh:
                    for line in fh:
                        if k >= cap:
                            break
                        try:
                            d = loads(line)
                            lab = d.get("label")
                            if lab not in (0, 1):
                                continue
                            if not (d.get("general") or {}).get("is_pe"):
                                continue
                            X.append(np.asarray(features_from_json(d), dtype=np.float64))
                            y.append(lab)
                            meta.append((ftype, member[:21], d.get("sha256", "")))
                            k += 1
                        except Exception:
                            bad += 1
                say(f"{split} {ftype} {member[:21]} kept={k} total={len(y)} bad={bad}")
        Xa = np.asarray(X, dtype=np.float64)
        assert Xa.shape[1] == N_FEATURES
        np.save(os.path.join(out, f"{split}_y.npy"), np.asarray(y, dtype=np.int8))
        with open(os.path.join(out, f"{split}_meta.tsv"), "w", encoding="utf-8") as fh:
            for m in meta:
                fh.write("\t".join(m) + "\n")
        np.save(done_flag, Xa)
        say(f"{split}: saved {Xa.shape}, malicious={int(sum(y))}, benign={len(y) - int(sum(y))}, bad={bad}")
    say("DONE")


if __name__ == "__main__":
    main()
