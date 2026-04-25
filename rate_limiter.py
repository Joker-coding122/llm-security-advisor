"""
LLM Security Advisor — 速率限制模块（Sliding Window）
======================================================
使用滑动窗口算法，对每个 session_id 限制单位时间内的请求次数。

为什么用滑动窗口？
  - 实现简单，零依赖
  - 相比固定窗口，不会出现"窗口边界双倍突刺"
  - 平均延迟低（O(N) 队列操作，N = 窗口内请求数）

为什么按 session_id 而不是 IP？
  - Streamlit 应用本地无 IP 概念，但有 st.session_state
  - 每个浏览器标签页 = 一个独立 session_id
  - 公开部署后可叠加 IP 维度形成双层限流

线程安全：
  - 用 threading.Lock 保护内部状态字典
  - 适配 Streamlit 多脚本运行环境
"""

import time
import threading
import uuid
from collections import deque
from typing import Deque, Dict


class SlidingWindowRateLimiter:
    """每个 key 在 window_seconds 秒内最多 max_requests 次。"""

    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> dict:
        """检查是否允许通过。不消费配额，仅查看状态。"""
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return {
                    "allowed": True,
                    "used": 0,
                    "limit": self.max_requests,
                    "remaining": self.max_requests,
                    "retry_after": 0,
                }
            self._evict_old(bucket, now)
            used = len(bucket)
            allowed = used < self.max_requests
            retry_after = 0
            if not allowed:
                # 最早一条何时滑出窗口
                retry_after = max(0, int(bucket[0] + self.window_seconds - now) + 1)
            return {
                "allowed": allowed,
                "used": used,
                "limit": self.max_requests,
                "remaining": max(0, self.max_requests - used),
                "retry_after": retry_after,
            }

    def acquire(self, key: str) -> dict:
        """尝试占用一个配额。allowed=True 时已计入，False 时未计入。"""
        now = time.time()
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            self._evict_old(bucket, now)
            if len(bucket) >= self.max_requests:
                retry_after = max(0, int(bucket[0] + self.window_seconds - now) + 1)
                return {
                    "allowed": False,
                    "used": len(bucket),
                    "limit": self.max_requests,
                    "remaining": 0,
                    "retry_after": retry_after,
                }
            bucket.append(now)
            return {
                "allowed": True,
                "used": len(bucket),
                "limit": self.max_requests,
                "remaining": self.max_requests - len(bucket),
                "retry_after": 0,
            }

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def _evict_old(self, bucket: Deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()


import os as _os

# 全局单例：整个应用共享同一个限流器
# 阈值通过环境变量可调，方便压测/部署不改代码：
#   RATE_LIMIT_MAX     默认 20 次
#   RATE_LIMIT_WINDOW  默认 60 秒
_MAX = int(_os.getenv("RATE_LIMIT_MAX", "20"))
_WINDOW = int(_os.getenv("RATE_LIMIT_WINDOW", "60"))
_GLOBAL_LIMITER = SlidingWindowRateLimiter(max_requests=_MAX, window_seconds=_WINDOW)


def get_limiter() -> SlidingWindowRateLimiter:
    return _GLOBAL_LIMITER


def new_session_id() -> str:
    """给每个 Streamlit 浏览器标签页生成稳定 session_id。"""
    return uuid.uuid4().hex[:12]
