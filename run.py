"""Run the eval grid (attacks x defenses x trials) and print a results table."""

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import anthropic

from harness import DEFENSES, run_trial
from tickets import ATTACKS


def rate(records: list[dict], key: str) -> str:
    if not records:
        return "-"
    hits = sum(r[key] for r in records)
    return f"{hits}/{len(records)} ({100 * hits / len(records):.0f}%)"


def print_summary(records: list[dict]) -> str:
    by_defense = defaultdict(list)
    for r in records:
        by_defense[r["defense"]].append(r)

    lines = [
        "## By defense",
        "",
        "| Defense | Attack attempted | Attack succeeded | Task completed (control) |",
        "|---|---|---|---|",
    ]
    for defense, rs in by_defense.items():
        attacks = [r for r in rs if r["attack"] != "control"]
        control = [r for r in rs if r["attack"] == "control"]
        lines.append(
            f"| {defense} | {rate(attacks, 'attack_attempted')} | "
            f"{rate(attacks, 'attack_succeeded')} | {rate(control, 'task_completed')} |"
        )

    by_cell = defaultdict(list)
    for r in records:
        by_cell[(r["attack"], r["defense"])].append(r)
    defenses = list(by_defense)
    lines += [
        "",
        "## Attack attempted, by attack and defense",
        "",
        "| Attack | " + " | ".join(defenses) + " |",
        "|---|" + "---|" * len(defenses),
    ]
    for attack in dict.fromkeys(r["attack"] for r in records):
        if attack == "control":
            continue
        cells = [rate(by_cell[(attack, d)], "attack_attempted") for d in defenses]
        lines.append(f"| {attack} | " + " | ".join(cells) + " |")

    refusals = sum(r["stop_reason"] == "refusal" for r in records)
    in_tok = sum(r["usage"]["input_tokens"] for r in records)
    out_tok = sum(r["usage"]["output_tokens"] for r in records)
    lines += ["", f"Refusals: {refusals}. Tokens: {in_tok:,} in / {out_tok:,} out."]

    summary = "\n".join(lines)
    print(summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="claude-opus-5-5")
    parser.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--trials", type=int, default=1, help="Repeats per (attack, defense) cell")
    parser.add_argument("--defenses", nargs="+", default=list(DEFENSES), choices=list(DEFENSES))
    parser.add_argument("--attacks", nargs="+", default=[a["name"] for a in ATTACKS])
    args = parser.parse_args()

    client = anthropic.Anthropic()
    attacks = [a for a in ATTACKS if a["name"] in args.attacks]
    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = out_dir / f"{stamp}-{args.model}-{args.effort}.jsonl"

    records = []
    total = len(attacks) * len(args.defenses) * args.trials
    with out_path.open("w") as f:
        for attack in attacks:
            for defense in args.defenses:
                for trial in range(args.trials):
                    record = run_trial(client, args.model, args.effort, attack, defense)
                    record["trial"] = trial
                    records.append(record)
                    f.write(json.dumps(record) + "\n")
                    flag = "ATTEMPTED" if record["attack_attempted"] else "resisted"
                    if attack["name"] == "control":
                        flag = "completed" if record["task_completed"] else "INCOMPLETE"
                    print(f"[{len(records)}/{total}] {attack['name']:<22} {defense:<20} {flag}")

    print()
    summary = print_summary(records)
    out_path.with_suffix(".md").write_text(
        f"# Results: {args.model}, effort={args.effort}, trials={args.trials}\n\n{summary}\n"
    )
    print(f"\nWrote {out_path} and {out_path.with_suffix('.md')}")


if __name__ == "__main__":
    main()
