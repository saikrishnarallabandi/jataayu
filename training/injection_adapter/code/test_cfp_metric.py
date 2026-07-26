"""Unit tests for the counterfactual-pair selection metric (no GPU, no model).

The point of paired accuracy is that it cannot be gamed by either failure mode, so the tests are
adversarial simulations rather than fixture checks: a `trigger => benign` shortcut scorer (v0.1's
pathology) and an over-defending scorer must BOTH score ~0, or the metric does not do the job it
was added for.

Run:  /home/user/envs/jataayu/bin/python code/test_cfp_metric.py
"""

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from train_lora import (
    cfp_family,
    cfp_paired_accuracy,
    fast_cfp_subset,
    flatten_cfp_arms,
    load_cfp_pairs,
    select_metric,
)

PILOT = HERE.parent / "data" / "pilot" / "counterfactual_pairs.pilot.jsonl"
FAILED = []


def check(name, got, want, tol=0.0):
    ok = abs(got - want) <= tol if isinstance(got, float) else got == want
    print(
        f"  [{'PASS' if ok else 'FAIL'}] {name}: got={got!r} want={want!r}"
        f"{f' +-{tol}' if tol else ''}"
    )
    if not ok:
        FAILED.append(name)


def score_all(pairs, fn):
    return [fn(a) for a in flatten_cfp_arms(pairs)]


def main():
    pairs, stats = load_cfp_pairs(PILOT)
    print(f"[load] {PILOT.name}: {stats}\n")

    # ---- the four required scorers, on the real 42 pilot pairs ----
    print("[synthetic scorers on the 42 real pilot pairs]")
    # every arm carries the same surface trigger; the shortcut model reads the trigger, not intent,
    # so it calls BOTH arms benign -> every attack arm wrong.
    check(
        "shortcut 'trigger => benign' -> ~0.0",
        cfp_paired_accuracy(pairs, score_all(pairs, lambda a: 0.01))[0],
        0.0,
    )
    check(
        "over-defend everything -> ~0.0",
        cfp_paired_accuracy(pairs, score_all(pairs, lambda a: 0.99))[0],
        0.0,
    )
    check(
        "perfect intent reader -> 1.0",
        cfp_paired_accuracy(
            pairs, score_all(pairs, lambda a: 0.9 if int(a["label"]) == 1 else 0.1)
        )[0],
        1.0,
    )
    rng = random.Random(7)
    accs = [
        cfp_paired_accuracy(pairs, score_all(pairs, lambda a: rng.random()))[0] for _ in range(200)
    ]
    check("random scorer -> ~0.25 (mean of 200 draws)", sum(accs) / len(accs), 0.25, tol=0.02)

    # a coin-flip-per-arm model gets a 2-arm pair right 1/4 of the time; that 0.25 floor is the
    # number a real checkpoint has to beat before it is reading intent at all.
    print("\n[metric properties]")
    perfect = [0.9 if int(a["label"]) == 1 else 0.1 for a in flatten_cfp_arms(pairs)]
    agg, fam, n = cfp_paired_accuracy(pairs, perfect)
    check("n_pairs reported", n, 42)
    # breaking ONE arm must cost exactly one pair -- 41/42, not 83/84: the pair is the unit.
    broken = list(perfect)
    broken[0] = 0.1
    check("one broken arm costs exactly one pair", cfp_paired_accuracy(pairs, broken)[0], 41 / 42)
    check("families present", sorted(fam), ["authority", "disregard", "exfil"])

    # tau boundary: attack arm at exactly 0.5 is CORRECT (p>=tau), benign at 0.5 is WRONG (p<tau).
    two = [p for p in pairs if len(p["arms"]) == 2][:1]
    check(
        "tau boundary: p=0.5 on both arms -> attack ok, benign wrong -> pair fails",
        cfp_paired_accuracy(two, [0.5] * 2)[0],
        0.0,
    )

    # ---- 3-arm pair must not crash (an exfil third arm is being added) ----
    print("\n[3+ arm tolerance]")

    def arm(label, cls, pid="synthetic_3arm"):
        return {
            "id": f"{pid}:{label}:{cls}",
            "pair_id": pid,
            "text": "t",
            "label": label,
            "class": cls,
            "attack_type": "x",
            "source": "test",
            "split": "dev",
        }

    three = [
        {
            "pair_id": "synthetic_3arm",
            "family": "exfil",
            "arms": [arm(1, "exfil:attack"), arm(0, "exfil:benign"), arm(1, "exfil:attack2")],
        }
    ]
    check("3-arm all correct -> 1.0", cfp_paired_accuracy(three, [0.9, 0.1, 0.9])[0], 1.0)
    check(
        "3-arm with ONLY the third arm wrong -> 0.0",
        cfp_paired_accuracy(three, [0.9, 0.1, 0.1])[0],
        0.0,
    )

    # a 3-arm pair loaded end-to-end from a file, exercising the grouping path too
    tmp = Path("/tmp/claude-1000/-home2-srallaba-projects-project-ascent/cfp_3arm.jsonl")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(
        "".join(
            json.dumps(r) + "\n"
            for r in [
                arm(1, "exfil:attack"),
                arm(0, "exfil:benign"),
                arm(1, "exfil:attack2"),
                arm(1, "authority:system_colon:attack", "p2"),
                arm(0, "authority:system_colon:benign", "p2"),
            ]
        )
    )
    lp, lstats = load_cfp_pairs(tmp)
    check("loader groups a 3-arm pair", lstats["arm_counts"], [2, 3])
    check("loader n_pairs", lstats["n_pairs"], 2)
    check("3-arm scored via loader", cfp_paired_accuracy(lp, [0.9, 0.1, 0.9, 0.9, 0.1])[0], 1.0)

    # ---- degenerate / malformed input ----
    print("\n[degenerate input]")
    solo = tmp.parent / "cfp_solo.jsonl"
    solo.write_text(
        "".join(
            json.dumps(r) + "\n"
            for r in [
                arm(1, "exfil:attack", "lonely"),  # no benign twin
                arm(1, "authority:x:attack", "p3"),
                arm(0, "authority:x:benign", "p3"),
            ]
        )
    )
    sp, sstats = load_cfp_pairs(solo)
    check("one-polarity group dropped (not scored as a pair)", sstats["n_pairs"], 1)
    check("...and counted", sstats["n_degenerate"], 1)
    check(
        "family split across arms -> 'mixed' bucket",
        load_cfp_pairs_mixed_family(tmp.parent),
        "mixed",
    )
    try:
        cfp_paired_accuracy(pairs, [0.5] * 3)
        check("misaligned scores raise", "no raise", "ValueError")
    except ValueError:
        check("misaligned scores raise", "ValueError", "ValueError")

    print("\n[family derivation]")
    check("3-segment class", cfp_family({"class": "authority:system_colon:attack"}), "authority")
    check("2-segment class", cfp_family({"class": "exfil:benign"}), "exfil")
    check("missing class", cfp_family({}), "unknown")

    print("\n[fast subset determinism / pair integrity]")
    a1 = fast_cfp_subset(pairs, 20, 20260715)
    a2 = fast_cfp_subset(pairs, 20, 20260715)
    b = fast_cfp_subset(pairs, 20, 999)
    check("same seed -> same pairs", [p["pair_id"] for p in a1], [p["pair_id"] for p in a2])
    check("cap respected (rows <= 20)", len(flatten_cfp_arms(a1)) <= 20, True)
    check(
        "different seed -> different subset",
        [p["pair_id"] for p in a1] != [p["pair_id"] for p in b],
        True,
    )
    check(
        "no pair is split (every group keeps all arms)",
        all(
            len(p["arms"]) == len(next(q for q in pairs if q["pair_id"] == p["pair_id"])["arms"])
            for p in a1
        ),
        True,
    )
    check("cap=0 -> all pairs", len(fast_cfp_subset(pairs, 0, 1)), 42)

    test_selection_ladder()
    test_callback_injects_metric(pairs)

    print("\n" + ("ALL PASS" if not FAILED else f"FAILED: {FAILED}"))
    return 1 if FAILED else 0


def test_selection_ladder():
    print("\n[selection priority]")
    d, o, c = [{"label": 1}], [{"label": 0}], [{"pair_id": "x"}]
    check("cfp wins over everything", select_metric(c, o, d), "eval_cfp_paired_acc")
    check("cfp alone", select_metric(c, None, None), "eval_cfp_paired_acc")
    check("no cfp + od -> old constrained", select_metric(None, o, d), "eval_dev_constrained")
    check("no cfp, dev only -> old recall", select_metric(None, None, d), "eval_dev_recall")
    check("nothing -> old auc", select_metric(None, None, None), "eval_roc_auc")


def test_callback_injects_metric(pairs):
    """Drive the real callback with a stubbed model, so the thing under test is the wiring HF
    actually reads: does metrics['eval_cfp_paired_acc'] exist (load_best/EarlyStopping KeyError if
    not), and is the OD floor really demoted rather than still gating."""
    print("\n[callback wiring (stubbed model, no GPU)]")
    import train_lora

    fake_scores = {}  # text -> score, set per scenario

    def fake_injection_scores(model, tok, texts, pos_id, neg_id, **kw):
        return [{"score": fake_scores.get(t, 0.5)} for t in texts]

    class FakeTrainer:
        def __init__(self):
            self.model = FakeModel()
            self.logged = {}

        def log(self, d):
            self.logged.update(d)

    class FakeModel:
        training = False

        def parameters(self):
            return iter([_FakeParam()])

        def eval(self):
            pass

        def train(self):
            pass

    class _FakeParam:
        device = "cpu"

    orig = train_lora.injscore.injection_scores
    train_lora.injscore.injection_scores = fake_injection_scores
    try:
        # single-class val on purpose: that skips the pre-existing val/auc branch, which needs
        # sklearn (absent from this env). The cfp path itself depends on numpy only.
        val_rows = [{"text": "v1", "label": 1}]
        od_rows = [{"text": f"od{i}", "label": 0} for i in range(10)]
        fake_scores["v1"] = 0.9
        for i in range(10):  # 2/10 NotInject flagged -> od_acc = 0.8
            fake_scores[f"od{i}"] = 0.9 if i < 2 else 0.1
        # perfect intent reader on the pairs
        for a in flatten_cfp_arms(pairs):
            fake_scores[a["text"]] = 0.9 if int(a["label"]) == 1 else 0.1

        tr = FakeTrainer()
        cb = train_lora._InjEvalCallback(
            tr,
            None,
            val_rows,
            None,
            1,
            2,
            1024,
            od_dev_rows=od_rows,
            od_acc_floor=0.97,
            cfp_pairs=pairs,
        )
        metrics = {}

        class S:
            global_step = 50

        cb.on_evaluate(None, S(), None, metrics=metrics)
        check("eval_cfp_paired_acc injected into metrics", metrics.get("eval_cfp_paired_acc"), 1.0)
        check(
            "old constrained metric NOT injected under cfp",
            "eval_dev_constrained" in metrics,
            False,
        )
        check(
            "NotInject od_acc REPORTED at tau=0.5", tr.logged.get("dev/notinject_od_acc@0.5"), 0.8
        )
        check(
            "od_acc 0.8 < floor 0.97 did NOT gate selection (paired acc still 1.0)",
            metrics.get("eval_cfp_paired_acc"),
            1.0,
        )
        check(
            "per-family series logged",
            sorted(k for k in tr.logged if k.startswith("dev/cfp_paired_acc.")),
            [
                "dev/cfp_paired_acc.authority",
                "dev/cfp_paired_acc.disregard",
                "dev/cfp_paired_acc.exfil",
            ],
        )
        check("arm-polarity series logged", tr.logged.get("dev/cfp_arm_acc.attack"), 1.0)

        # shortcut model through the SAME callback path -> selection metric must collapse to 0
        for a in flatten_cfp_arms(pairs):
            fake_scores[a["text"]] = 0.01
        m2 = {}
        cb.on_evaluate(None, S(), None, metrics=m2)
        check(
            "shortcut scorer through callback -> eval_cfp_paired_acc 0.0",
            m2.get("eval_cfp_paired_acc"),
            0.0,
        )
    finally:
        train_lora.injscore.injection_scores = orig


def load_cfp_pairs_mixed_family(d):
    p = d / "cfp_mixedfam.jsonl"
    rows = [
        {"id": "a", "pair_id": "m", "text": "t", "label": 1, "class": "authority:x:attack"},
        {"id": "b", "pair_id": "m", "text": "t", "label": 0, "class": "exfil:benign"},
    ]
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return load_cfp_pairs(p)[0][0]["family"]


if __name__ == "__main__":
    sys.exit(main())
