"""
LLM Security Advisor — 安全网关自动化评估脚本
============================================
用法（在项目根目录运行）：
    python tests/run_eval.py

功能：
    1. 加载 tests/attack_dataset.json 中的 30 条样例
    2. 对每条调用 security_gateway.detect_injection
    3. 与 expected (block / pass) 对比，自动判定对错
    4. 在终端输出分类结果表 + 关键指标
    5. 写入 tests/eval_report.csv（详情）与 tests/eval_summary.json（总览）

不调用 LLM、不消耗 API token —— 纯规则层评估。
"""

import csv
import json
import sys
import time
from pathlib import Path

# 让脚本既能从根目录跑，也能从 tests/ 目录跑
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security_gateway import detect_injection  # noqa: E402

DATASET_PATH = ROOT / "tests" / "attack_dataset.json"
CSV_REPORT = ROOT / "tests" / "eval_report.csv"
JSON_SUMMARY = ROOT / "tests" / "eval_summary.json"


def predict(text: str) -> str:
    """把 detect_injection 的结果归一化为 block / pass。"""
    return "block" if detect_injection(text)["risk"] == "high" else "pass"


def evaluate():
    data = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    samples = data["samples"]

    rows = []
    tp = fp = tn = fn = 0  # 以"攻击=正样本"为视角
    latencies = []

    for s in samples:
        t0 = time.perf_counter()
        pred = predict(s["input"])
        latency_ms = (time.perf_counter() - t0) * 1000
        latencies.append(latency_ms)

        expected = s["expected"]
        correct = pred == expected

        # 混淆矩阵（攻击为正类）
        if expected == "block" and pred == "block":
            tp += 1
        elif expected == "pass" and pred == "block":
            fp += 1
        elif expected == "pass" and pred == "pass":
            tn += 1
        elif expected == "block" and pred == "pass":
            fn += 1

        rows.append({
            "id": s["id"],
            "category": s["category"],
            "input": s["input"],
            "expected": expected,
            "predicted": pred,
            "correct": correct,
            "latency_ms": round(latency_ms, 3),
            "note": s.get("note", ""),
        })

    total = len(samples)
    correct_count = tp + tn
    accuracy = correct_count / total if total else 0
    recall = tp / (tp + fn) if (tp + fn) else 0          # 攻击拦截率
    precision = tp / (tp + fp) if (tp + fp) else 0        # 拦截精度
    fpr = fp / (fp + tn) if (fp + tn) else 0              # 误报率
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    # ---- 终端输出 ----
    print("\n" + "=" * 64)
    print("  LLM Security Advisor — 安全网关评估结果")
    print("=" * 64)
    print(f"  样例总数        : {total}")
    print(f"  攻击样例 / 正常 : {tp + fn} / {tn + fp}")
    print(f"  正确判定数      : {correct_count}")
    print(f"  混淆矩阵        : TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print("-" * 64)
    print(f"  Accuracy         : {accuracy:.2%}")
    print(f"  Attack Recall    : {recall:.2%}    （攻击拦截率，越高越好）")
    print(f"  Precision        : {precision:.2%}    （拦截精度）")
    print(f"  False Positive Rate: {fpr:.2%}    （误报率，越低越好）")
    print(f"  F1 Score         : {f1:.4f}")
    print("-" * 64)
    print(f"  平均检测耗时     : {sum(latencies) / len(latencies):.3f} ms")
    print(f"  最大检测耗时     : {max(latencies):.3f} ms")
    print("=" * 64)

    # ---- 失败样例打印 ----
    failed = [r for r in rows if not r["correct"]]
    if failed:
        print("\n[未通过样例]")
        for r in failed:
            print(f"  {r['id']}  expected={r['expected']}  got={r['predicted']}  "
                  f"category={r['category']}  input={r['input'][:60]}")
    else:
        print("\n[全部样例通过 ✅]")

    # ---- 写 CSV 详情 ----
    with CSV_REPORT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["id", "category", "expected", "predicted", "correct",
                        "latency_ms", "input", "note"],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    # ---- 写 JSON 总览 ----
    summary = {
        "total": total,
        "attacks": tp + fn,
        "benigns": tn + fp,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(accuracy, 4),
        "attack_recall": round(recall, 4),
        "precision": round(precision, 4),
        "false_positive_rate": round(fpr, 4),
        "f1": round(f1, 4),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 4),
        "max_latency_ms": round(max(latencies), 4),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    JSON_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\n详细结果已写入 : {CSV_REPORT}")
    print(f"总览数据已写入 : {JSON_SUMMARY}")

    # 返回 exit code：有任何失败用例则非 0，方便接 CI
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(evaluate())
