#!/usr/bin/env python3
"""Detect misuse of one ServiceAccount in Kubernetes audit logs.

Usage (from the project root):
    python3 category3/detector/detect.py category3/results/raw/*.jsonl \
        --json category3/results/summary.json > category3/results/report.md

Steps: preprocess, make sessions, apply the rules, evaluate the rule sets.
The file name prefix gives the label: normal* is normal, abnormal* is attack.
The script uses only the Python standard library.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

TARGET_USER = "system:serviceaccount:pbl-security:pbl-crypto-platform-app"
SA_NAME = "pbl-crypto-platform-app"
JTI_KEY = "authentication.kubernetes.io/credential-id"

# D4 parameters
WINDOW_SEC = 10.0
REPEAT_TH = 3    # same (verb, resource) in one window
TOTAL_TH = 10    # all requests in one window
DISTINCT_TH = 2  # D4' only: resource types in one window

RULES = {
    "D1": ("민감 리소스 접근", "High"),
    "D2": ("원격 실행 시도", "High"),
    "D3": ("인가 거부", "Medium"),
    "D4": ("반복 열거", "Medium"),
    "D5": ("호출 도구 이탈", "Low"),
    "D6": ("권한 탐색", "Medium"),
    "D4'": ("반복 열거 (개선안)", "Medium"),
}
SEV_RANK = {"High": 3, "Medium": 2, "Low": 1}

RULE_SETS = {
    "A": (["D3"], "D3만 사용"),
    "B": (["D1", "D2", "D3", "D4", "D5"], "D6 없음"),
    "C": (["D1", "D2", "D3", "D4", "D5", "D6"], "제안 구성"),
    "D": (["D1", "D2", "D3", "D5", "D6"], "C에서 D4 제외"),
    "E": (["D1", "D2", "D3", "D4'", "D5", "D6"], "C에서 D4를 D4'로 교체"),
}
MAIN_SET = "C"


def parse_ts(ts):
    ts = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt)
        except ValueError:
            continue
    raise ValueError(ts)


def scenario_of(path):
    return os.path.basename(path).rsplit(".", 1)[0]


def label_of(scenario):
    return "attack" if scenario.startswith("abnormal") else "normal"


def res_key(ev):
    """Return "resource" or "resource/subresource"."""
    o = ev.get("objectRef") or {}
    r = o.get("resource", "")
    return f"{r}/{o['subresource']}" if o.get("subresource") else r


def code_of(ev):
    return (ev.get("responseStatus") or {}).get("code")


def decision_of(ev):
    return (ev.get("annotations") or {}).get("authorization.k8s.io/decision", "")


def jti_of(ev):
    vals = ((ev.get("user") or {}).get("extra") or {}).get(JTI_KEY) or []
    return vals[0].replace("JTI=", "") if vals else None


def short_ua(ua):
    return (ua or "").split(" ")[0]


def load(paths):
    """Read the log files and keep the requests of the target ServiceAccount.

    Step 1: keep events where user.username is the target ServiceAccount.
    Step 2: keep events where stage is ResponseComplete.
    Step 3: keep events that have an objectRef.
    """
    stats = Counter()
    dropped = Counter()    # (stage, resource) of the events that step 2 removes
    not_actor = Counter()  # events that contain SA_NAME but have a different user
    events = []
    for path in paths:
        scen = scenario_of(path)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                stats["lines"] += 1
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    stats["bad_json"] += 1
                    continue
                if SA_NAME in line:
                    stats["string_match"] += 1
                user = (ev.get("user") or {}).get("username", "")
                if user != TARGET_USER:
                    if SA_NAME in line:
                        not_actor[(user, ev.get("verb", ""), res_key(ev) or "-")] += 1
                    continue
                stats["actor_match"] += 1
                if ev.get("stage") != "ResponseComplete":
                    stats["drop_stage"] += 1
                    dropped[(ev.get("stage"), res_key(ev) or "(non-resource)")] += 1
                    continue
                if not ev.get("objectRef"):
                    stats["drop_nonresource"] += 1
                    continue
                stats["kept"] += 1
                ev["_t"] = parse_ts(ev["requestReceivedTimestamp"])
                ev["_file"] = os.path.basename(path)
                ev["_scenario"] = scen
                events.append(ev)
    return events, stats, dropped, not_actor


def sessionize(events):
    """Group the events by (file, token JTI).

    The key includes the file because the example logs in category3/logs
    use the same JTI in different files.
    """
    sessions = defaultdict(list)
    for ev in events:
        sessions[(ev["_file"], jti_of(ev) or "no-jti")].append(ev)
    out = []
    for (fname, jti), evs in sessions.items():
        evs.sort(key=lambda e: e["_t"])
        scen = evs[0]["_scenario"]
        out.append({"file": fname, "jti": jti, "scenario": scen,
                    "label": label_of(scen), "events": evs})
    order = lambda s: (0 if s["label"] == "normal" else 1, s["scenario"], s["jti"])
    return sorted(out, key=order)


def event_rules(ev):
    """Return the per-event rules (D1, D2, D3, D5, D6) that match."""
    hits = []
    o = ev.get("objectRef") or {}
    if o.get("resource") == "secrets":
        hits.append("D1")
    if o.get("subresource") in ("exec", "attach", "portforward"):
        hits.append("D2")
    if decision_of(ev) == "forbid" or code_of(ev) == 403:
        hits.append("D3")
    if not (ev.get("userAgent") or "").startswith("kubectl/"):
        hits.append("D5")
    if o.get("resource") in ("selfsubjectrulesreviews", "selfsubjectaccessreviews"):
        hits.append("D6")
    return hits


def window_stats(evs, window=WINDOW_SEC):
    """Count the events in the last `window` seconds at each event.

    Return one tuple for each event:
    (repeats of its (verb, resource), all requests, resource types, largest repeat count).
    """
    rows = []
    left = 0
    rep = Counter()
    res = Counter()
    for right, ev in enumerate(evs):
        key = (ev.get("verb"), res_key(ev))
        rep[key] += 1
        res[res_key(ev)] += 1
        while (ev["_t"] - evs[left]["_t"]).total_seconds() > window:
            old = evs[left]
            k_old = (old.get("verb"), res_key(old))
            rep[k_old] -= 1
            res[res_key(old)] -= 1
            if rep[k_old] == 0:
                del rep[k_old]
            if res[res_key(old)] == 0:
                del res[res_key(old)]
            left += 1
        rows.append((rep[key], right - left + 1, len(res), max(rep.values())))
    return rows


def judge_session(s, repeat_th=REPEAT_TH, total_th=TOTAL_TH, distinct_th=DISTINCT_TH):
    """Apply all rules to one session. Add the evidence and the window maximums."""
    evs = s["events"]
    evidence = defaultdict(list)
    for ev in evs:
        for r in event_rules(ev):
            evidence[r].append(ev)
    max_rep = max_tot = max_dist = 0
    for ev, (rep_now, tot, dist, rep_max) in zip(evs, window_stats(evs)):
        max_rep, max_tot, max_dist = max(max_rep, rep_max), max(max_tot, tot), max(max_dist, dist)
        if rep_now >= repeat_th or tot >= total_th:
            evidence["D4"].append(ev)
        if (rep_now >= repeat_th and dist >= distinct_th) or tot >= total_th:
            evidence["D4'"].append(ev)
    s.update({"evidence": dict(evidence), "hits": set(evidence),
              "max_rep": max_rep, "max_tot": max_tot, "max_dist": max_dist,
              "n": len(evs),
              "duration": (evs[-1]["_t"] - evs[0]["_t"]).total_seconds() if evs else 0.0})
    return s


def verdict(s, rules):
    """Return (flagged, severity, matched rules) for one rule set."""
    hit = [r for r in rules if r in s["hits"]]
    if not hit:
        return False, None, []
    sev = max((RULES[r][1] for r in hit), key=lambda x: SEV_RANK[x])
    return True, sev, hit


def confusion(sessions, rules):
    tp = fp = fn = tn = 0
    for s in sessions:
        pred, _, _ = verdict(s, rules)
        if s["label"] == "attack":
            tp, fn = (tp + 1, fn) if pred else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if pred else (fp, tn + 1)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)}


def outcome(label, pred):
    if label == "attack":
        return "TP" if pred else "FN"
    return "FP" if pred else "TN"


def threshold_sweep(sessions, rng=range(2, 9)):
    """Evaluate set C for each D4 repeat threshold in rng. Keep TOTAL_TH."""
    rows = []
    for k in rng:
        tmp = [judge_session(dict(s), repeat_th=k) for s in sessions]
        rows.append({"repeat_th": k, **confusion(tmp, RULE_SETS[MAIN_SET][0])})
    return rows


def fmt_ev(ev):
    return "| `{}` | {} | {} | {} | {} | {} | {} |".format(
        ev["auditID"][:8], ev["_t"].strftime("%H:%M:%S.%f")[:-3], ev.get("verb"),
        res_key(ev), code_of(ev), decision_of(ev), short_ua(ev.get("userAgent")))


def report(paths, stats, dropped, not_actor, sessions, sweep):
    L = []
    w = L.append
    w("# Category 3 탐지 결과")
    w("")
    w(f"- 생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"- 입력 파일: {len(paths)}개")
    w(f"- 대상: `{TARGET_USER}`")
    w(f"- D4: {WINDOW_SEC:.0f}초 창, 같은 (verb, resource) ≥ {REPEAT_TH}회 또는 전체 ≥ {TOTAL_TH}건")
    w("")

    w("## 1. 전처리")
    w("")
    w("| 단계 | 건수 |")
    w("|---|---:|")
    w(f"| 수집 구간 전체 | {stats['lines']} |")
    w(f"| SA 이름 포함 | {stats['string_match']} |")
    w(f"| (1) user.username 일치 | {stats['actor_match']} |")
    w(f"| (2) 제거: ResponseComplete 아님 | {stats['drop_stage']} |")
    w(f"| (3) 제거: objectRef 없음 | {stats['drop_nonresource']} |")
    w(f"| **탐지 입력** | **{stats['kept']}** |")
    w("")
    w(f"SA 이름을 포함하지만 행위자가 다른 이벤트: {sum(not_actor.values())}건")
    w("")
    w("| user | verb | resource | 건수 |")
    w("|---|---|---|---:|")
    for (u, v, r), c in not_actor.most_common(10):
        w(f"| `{u}` | {v} | {r} | {c} |")
    w("")
    w("(2)에서 제거한 이벤트:")
    w("")
    w("| stage | resource | 건수 |")
    w("|---|---|---:|")
    for (st, r), c in sorted(dropped.items(), key=lambda x: -x[1]):
        w(f"| {st} | {r} | {c} |")
    w("")

    rules_c = RULE_SETS[MAIN_SET][0]
    w(f"## 2. 세션 판정 (세트 {MAIN_SET}: {', '.join(rules_c)})")
    w("")
    w("세션 = (파일, 토큰 JTI). 반복과 전체는 10초 창 최대값.")
    w("")
    w("| 시나리오 | 라벨 | JTI | 요청 | 지속(s) | 반복 | 전체 | D1 | D2 | D3 | D4 | D5 | D6 | 판정 | 심각도 | 결과 |")
    w("|---|---|---|---:|---:|---:|---:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|:-:|")
    for s in sessions:
        pred, sev, _ = verdict(s, rules_c)
        marks = ["●" if r in s["hits"] else "" for r in ["D1", "D2", "D3", "D4", "D5", "D6"]]
        w(f"| {s['scenario']} | {'공격' if s['label'] == 'attack' else '정상'} | `{s['jti'][:8]}` | {s['n']} | "
          f"{s['duration']:.1f} | {s['max_rep']} | {s['max_tot']} | " + " | ".join(marks)
          + f" | {'공격' if pred else '정상'} | {sev or '-'} | **{outcome(s['label'], pred)}** |")
    w("")

    w("## 3. 규칙별 경보")
    w("")
    w("| 규칙 | 이름 | 심각도 | 경보 세션 (정상/공격) | 근거 이벤트 |")
    w("|---|---|---|---|---:|")
    for r, (name, sev) in RULES.items():
        ns = sum(1 for s in sessions if r in s["hits"] and s["label"] == "normal")
        as_ = sum(1 for s in sessions if r in s["hits"] and s["label"] == "attack")
        ne = sum(len(s["evidence"].get(r, [])) for s in sessions)
        w(f"| {r} | {name} | {sev} | {ns} / {as_} | {ne} |")
    w("")

    w("## 4. 규칙 세트 비교")
    w("")
    n_norm = sum(1 for s in sessions if s["label"] == "normal")
    w(f"세션: 정상 {n_norm}, 공격 {len(sessions) - n_norm}")
    w("")
    w("| 세트 | 규칙 | 설명 | TP | FP | FN | TN | Precision | Recall | F1 |")
    w("|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|")
    for name, (rules, desc) in RULE_SETS.items():
        m = confusion(sessions, rules)
        w(f"| {name} | {', '.join(rules)} | {desc} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | "
          f"{m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} |")
    w("")
    w("시나리오별 결과:")
    w("")
    scen_names = sorted({s["scenario"] for s in sessions}, key=lambda x: (label_of(x) == "attack", x))
    w("| 시나리오 | 라벨 | " + " | ".join(RULE_SETS) + " |")
    w("|---|---|" + "|".join([":-:"] * len(RULE_SETS)) + "|")
    for sc in scen_names:
        ss = [s for s in sessions if s["scenario"] == sc]
        cells = []
        for rules, _ in RULE_SETS.values():
            outs = Counter(outcome(s["label"], verdict(s, rules)[0]) for s in ss)
            cells.append("/".join(k if len(ss) == 1 else f"{k}×{v}" for k, v in sorted(outs.items())))
        w(f"| {sc} | {'공격' if label_of(sc) == 'attack' else '정상'} | " + " | ".join(cells) + " |")
    w("")

    w("## 5. D4 임계값")
    w("")
    w("| 시나리오 | 10초 창 최대 반복 | 10초 창 최대 요청 | 10초 창 리소스 종류 | 세션 요청 |")
    w("|---|---:|---:|---:|---:|")
    for sc in scen_names:
        ss = [s for s in sessions if s["scenario"] == sc]

        def rng(key):
            lo, hi = min(s[key] for s in ss), max(s[key] for s in ss)
            return f"{lo}" if lo == hi else f"{lo}~{hi}"
        w(f"| {sc} | {rng('max_rep')} | {rng('max_tot')} | {rng('max_dist')} | {rng('n')} |")
    w("")
    w(f"반복 임계값 변경 (세트 {MAIN_SET}, 전체 임계값 {TOTAL_TH}):")
    w("")
    w("| 반복 임계값 | TP | FP | FN | TN | Precision | Recall |")
    w("|:-:|:-:|:-:|:-:|:-:|:-:|:-:|")
    for r in sweep:
        mark = " (설계값)" if r["repeat_th"] == REPEAT_TH else ""
        w(f"| {r['repeat_th']}{mark} | {r['TP']} | {r['FP']} | {r['FN']} | {r['TN']} | "
          f"{r['precision']:.2f} | {r['recall']:.2f} |")
    w("")

    w("## 6. 근거 이벤트 (규칙당 최대 3건)")
    w("")
    for s in sessions:
        pred, _, hit = verdict(s, rules_c)
        w(f"### {s['scenario']} (`{s['jti'][:8]}`): {outcome(s['label'], pred)} ({', '.join(hit) if hit else '일치 규칙 없음'})")
        w("")
        if not hit:
            w(f"요청 {s['n']}건, 10초 창 최대 반복 {s['max_rep']}, 최대 요청 {s['max_tot']}.")
            w("")
            continue
        w("| 규칙 | auditID | 시각(UTC) | verb | resource | code | decision | userAgent |")
        w("|---|---|---|---|---|---|---|---|")
        for r in hit:
            for ev in s["evidence"][r][:3]:
                w(f"| {r} " + fmt_ev(ev))
        w("")
    return "\n".join(L)


def summary_json(stats, sessions, sweep, dropped, not_actor):
    return {
        "stats": dict(stats),
        "dropped_by_stage": {f"{k[0]}|{k[1]}": v for k, v in dropped.items()},
        "string_only": sum(not_actor.values()),
        "sessions": [{
            "scenario": s["scenario"], "label": s["label"], "jti": s["jti"],
            "n": s["n"], "duration": s["duration"], "max_rep": s["max_rep"], "max_tot": s["max_tot"],
            "max_dist": s["max_dist"], "hits": sorted(s["hits"]),
            "outcome": {k: outcome(s["label"], verdict(s, v[0])[0]) for k, v in RULE_SETS.items()},
        } for s in sessions],
        "sets": {k: {"rules": v[0], "description": v[1], **confusion(sessions, v[0])} for k, v in RULE_SETS.items()},
        "sweep": sweep,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="results/raw/<scenario>.jsonl")
    ap.add_argument("--json", help="write the summary JSON to this path")
    args = ap.parse_args()

    events, stats, dropped, not_actor = load(args.files)
    sessions = [judge_session(s) for s in sessionize(events)]

    # One script run issues one token. A file with more than one JTI breaks this rule.
    for f, c in Counter(s["file"] for s in sessions).items():
        if c > 1:
            print(f"[warn] {f}: {c} JTIs", file=sys.stderr)

    sweep = threshold_sweep(sessions)
    print(report(args.files, stats, dropped, not_actor, sessions, sweep))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary_json(stats, sessions, sweep, dropped, not_actor), fh, ensure_ascii=False, indent=2)

    m = confusion(sessions, RULE_SETS[MAIN_SET][0])
    print(f"[detect] sessions={len(sessions)} set {MAIN_SET}: TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} "
          f"P={m['precision']:.2f} R={m['recall']:.2f}", file=sys.stderr)


if __name__ == "__main__":
    main()
