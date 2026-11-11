# -*- coding: utf-8 -*-
"""Train the Sour static-PE detector (LightGBM) and export it for the C# engine.

Temporal protocol (as EMBER2024 intends): train on the first weeks, validate on the
last 4 training weeks (early stopping + threshold selection), report on the later
test weeks, which the model never sees.

usage: python train.py <data_dir> <out_dir>
outputs: sour_model.json (trees), model_card.json (metrics, caps), parity.json (C# self-test vectors)
"""
import ctypes
import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from featspec import FEATURE_NAMES  # noqa: E402


def tpr_at_fpr(y, s, fpr_target):
    fpr, tpr, thr = roc_curve(y, s)
    i = np.searchsorted(fpr, fpr_target, side="right") - 1
    return float(tpr[max(i, 0)]), float(thr[max(i, 0)])


def main():
    data, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    try:
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x4000)
    except Exception:
        pass
    X = np.load(os.path.join(data, "train_X.npy"))
    y = np.load(os.path.join(data, "train_y.npy")).astype(int)
    Xt = np.load(os.path.join(data, "test_X.npy"))
    yt = np.load(os.path.join(data, "test_y.npy")).astype(int)
    meta = [l.rstrip("\n").split("\t") for l in open(os.path.join(data, "train_meta.tsv"), encoding="utf-8")]
    meta_t = [l.rstrip("\n").split("\t") for l in open(os.path.join(data, "test_meta.tsv"), encoding="utf-8")]
    weeks = np.array([m[1] for m in meta])
    uniq = sorted(set(weeks))
    val_weeks = set(uniq[-4:])
    is_val = np.array([w in val_weeks for w in weeks])
    print(f"train={int((~is_val).sum())} val={int(is_val.sum())} test={len(yt)} features={X.shape[1]}", flush=True)

    params = dict(objective="binary", learning_rate=0.05, num_leaves=64, min_data_in_leaf=40,
                  feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0,
                  num_threads=4, verbose=-1, seed=7, use_missing=False, zero_as_missing=False)
    dtr = lgb.Dataset(X[~is_val], y[~is_val], feature_name=FEATURE_NAMES)
    dva = lgb.Dataset(X[is_val], y[is_val], reference=dtr)
    t0 = time.time()
    bst = lgb.train(params, dtr, num_boost_round=1500, valid_sets=[dva],
                    callbacks=[lgb.early_stopping(60), lgb.log_evaluation(100)])
    print(f"trained {bst.best_iteration} trees in {time.time() - t0:.0f}s", flush=True)

    sv = bst.predict(X[is_val], num_iteration=bst.best_iteration)
    st = bst.predict(Xt, num_iteration=bst.best_iteration)
    # thresholds are fixed on VALIDATION, then reported on test
    _, thr_mal = tpr_at_fpr(y[is_val], sv, 0.001)
    _, thr_sus = tpr_at_fpr(y[is_val], sv, 0.01)

    def at(thr, yy, ss):
        pred = ss >= thr
        tp = int((pred & (yy == 1)).sum()); fp = int((pred & (yy == 0)).sum())
        return dict(threshold=float(thr), tpr=tp / max(int((yy == 1).sum()), 1), fpr=fp / max(int((yy == 0).sum()), 1), tp=tp, fp=fp)

    types_t = np.array([m[0] for m in meta_t])
    per_type = {}
    for t in sorted(set(types_t)):
        k = types_t == t
        per_type[t] = dict(n=int(k.sum()), auc=float(roc_auc_score(yt[k], st[k])),
                           malicious=at(thr_mal, yt[k], st[k]), suspicious=at(thr_sus, yt[k], st[k]))

    gain = bst.feature_importance("gain")
    order = np.argsort(-gain)
    card = dict(
        name="Sour static PE detector", algorithm="LightGBM gradient-boosted trees",
        trained=time.strftime("%Y-%m-%d"), n_features=len(FEATURE_NAMES), n_trees=int(bst.best_iteration),
        dataset="EMBER2024 raw features (Win32, Win64, Dot_Net)",
        sampling="first 2500 labelled PE records of every weekly file (cap stated, not the full corpus)",
        n_train=int((~is_val).sum()), n_val=int(is_val.sum()), n_test=int(len(yt)),
        train_weeks=[uniq[0], uniq[-5]], val_weeks=sorted(val_weeks),
        test_weeks=[min(m[1] for m in meta_t), max(m[1] for m in meta_t)],
        val_auc=float(roc_auc_score(y[is_val], sv)), test_auc=float(roc_auc_score(yt, st)),
        threshold_malicious=float(thr_mal), threshold_suspicious=float(thr_sus),
        threshold_rule="malicious = 0.1% FPR on validation; suspicious = 1% FPR on validation",
        test_at_malicious=at(thr_mal, yt, st), test_at_suspicious=at(thr_sus, yt, st),
        per_type=per_type,
        top_features=[dict(name=FEATURE_NAMES[i], gain=float(gain[i] / gain.sum())) for i in order[:25]],
    )
    json.dump(card, open(os.path.join(out, "model_card.json"), "w", encoding="utf-8"), indent=1)

    dump = bst.dump_model(num_iteration=bst.best_iteration)
    trees = []
    for t in dump["tree_info"]:
        sf, th, lc, rc, iv, lv = [], [], [], [], [], []

        def walk(node):
            """returns child reference: >=0 internal index, <0 = ~leaf index"""
            if "leaf_index" in node or "leaf_value" in node and "split_index" not in node:
                lv.append(float(node["leaf_value"]))
                return ~(len(lv) - 1)
            i = len(sf)
            assert node["decision_type"] == "<=", node["decision_type"]
            sf.append(int(node["split_feature"])); th.append(float(node["threshold"]))
            iv.append(float(node["internal_value"])); lc.append(0); rc.append(0)
            lc[i] = walk(node["left_child"]); rc[i] = walk(node["right_child"])
            return i

        walk(t["tree_structure"])
        trees.append(dict(f=sf, t=th, l=lc, r=rc, v=iv, leaf=lv))
    model = dict(format="sour-gbdt-1", features=FEATURE_NAMES, trees=trees,
                 threshold_malicious=float(thr_mal), threshold_suspicious=float(thr_sus))
    json.dump(model, open(os.path.join(out, "sour_model.json"), "w", encoding="utf-8"), separators=(",", ":"))

    rng = np.random.default_rng(3)
    idx = rng.choice(len(yt), 300, replace=False)
    parity = dict(rows=[dict(x=[float(v) for v in Xt[i]], p=float(st[i]), y=int(yt[i])) for i in idx])
    json.dump(parity, open(os.path.join(out, "parity.json"), "w", encoding="utf-8"), separators=(",", ":"))
    print(json.dumps({k: card[k] for k in ("n_trees", "val_auc", "test_auc", "test_at_malicious", "test_at_suspicious", "per_type")}, indent=1))
    print("top:", [f["name"] for f in card["top_features"][:12]])


if __name__ == "__main__":
    main()
