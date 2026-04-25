"""
LLM Security Advisor — 审计日志模块
====================================
把每一次请求按 JSONL 写到 logs/audit.log，便于事后追溯、统计、合规。

事件类型 event：
  - "allowed"       正常放行并已调用 LLM
  - "blocked"       被安全网关拦截
  - "rate_limited"  被限流拦截
  - "api_error"     LLM 调用失败

每行一个 JSON，字段：
  ts, event, session_id, ip, prompt, risk, category, rule, latency_ms, extra
"""

import json
import time
import threading
from pathlib import Path

# 项目根目录下的 logs/audit.log
LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "audit.log"

_LOCK = threading.Lock()  # 防止 Streamlit 多脚本运行时并发写


def _ensure_log_dir():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def log_event(
    event: str,
    prompt: str = "",
    session_id: str = "",
    ip: str = "",
    risk: str = "",
    category: str = "",
    rule: str = "",
    latency_ms: float | None = None,
    extra: dict | None = None,
) -> None:
    """追加一条审计日志（JSONL 格式）。失败不抛出，避免影响主流程。"""
    try:
        _ensure_log_dir()
        record = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": event,
            "session_id": session_id,
            "ip": ip,
            "prompt": (prompt or "")[:300],  # 防止巨长输入打爆日志
            "risk": risk,
            "category": category,
            "rule": rule,
            "latency_ms": round(latency_ms, 3) if latency_ms is not None else None,
            "extra": extra or {},
        }
        line = json.dumps(record, ensure_ascii=False)
        with _LOCK:
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        # 审计日志失败不能影响业务
        pass


def read_recent(n: int = 50) -> list[dict]:
    """读最近 n 条审计日志，给侧边栏展示用。"""
    if not LOG_FILE.exists():
        return []
    try:
        with LOG_FILE.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        recent = lines[-n:]
        return [json.loads(line) for line in recent if line.strip()]
    except Exception:
        return []


def stats() -> dict:
    """汇总日志事件计数。"""
    counts = {"allowed": 0, "blocked": 0, "rate_limited": 0, "api_error": 0, "total": 0}
    if not LOG_FILE.exists():
        return counts
    try:
        with LOG_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    counts["total"] += 1
                    ev = rec.get("event", "")
                    if ev in counts:
                        counts[ev] += 1
                except Exception:
                    continue
    except Exception:
        pass
    return counts
