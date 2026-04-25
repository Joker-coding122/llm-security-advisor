# 阶段 6 成果报告：API 限流 + 日志审计

## 一句话结论

为 `LLM Security Advisor` 增加调用侧防护层：基于滑动窗口的会话级速率限制 + JSONL 持久化审计日志，与阶段 4 的输入侧安全网关一起构成"双层防御 + 全链路审计"的完整安全闭环，并已通过实际压测验证限流生效。

---

## 1. 完整请求处理流水线

```
[用户输入]
   ↓
[① 限流网关  rate_limiter.acquire(session_id)]
   ├─ 拒绝 → ⏳ 提示 + 写 rate_limited 日志 → return
   ↓
[② 安全网关  detect_injection(prompt)]
   ├─ 拦截 → 🛡️ 提示 + 写 blocked 日志 → return
   ↓
[③ 调用 LLM API]
   ├─ 成功 → 写 allowed 日志（含 latency）
   └─ 异常 → 写 api_error 日志
   ↓
[审计日志：logs/audit.log（JSONL）]
```

## 2. 模块清单

| 文件 | 作用 |
|---|---|
| `rate_limiter.py` | 滑动窗口限流器，线程安全，支持环境变量配置阈值 |
| `audit_logger.py` | JSONL 审计日志读写 + 统计 |
| `app.py` | 集成两者，加入侧边栏"调用侧防护"面板 |

## 3. 限流设计

- **算法**：滑动窗口（Sliding Window）
- **粒度**：单会话（`session_id`），每个浏览器标签页独立计数
- **默认阈值**：20 次 / 60 秒
- **可配置**：`RATE_LIMIT_MAX`、`RATE_LIMIT_WINDOW` 环境变量
- **数据结构**：`deque` 时间戳队列，懒淘汰
- **线程安全**：`threading.Lock` 保护内部状态

### 设计权衡

| 选项 | 选择 | 理由 |
|---|---|---|
| 固定窗口 | ❌ | 边界双倍突刺 |
| 滑动窗口 | ✅ | 简单、平滑、零依赖 |
| 令牌桶 | ❌ | 实现复杂，本项目不需要突发支持 |

### 为什么按 session_id 而不是 IP

- Streamlit 本地无 IP 概念，但天然有 `st.session_state`
- 公开部署（Streamlit Cloud）后可叠加 IP 维度形成双层限流
- 当前实现可作为"应用层第一道闸门"，而非全部防御

## 4. 审计日志设计

- **格式**：JSONL（每行一个独立 JSON），ELK / Splunk / DuckDB 直接消费
- **位置**：`logs/audit.log`（已加入 `.gitignore`）
- **事件类型**：`allowed` / `blocked` / `rate_limited` / `api_error`
- **字段**：`ts / event / session_id / ip / prompt / risk / category / rule / latency_ms / extra`
- **健壮性**：写日志失败 try/except 静默吞掉，不影响业务
- **隐私**：prompt 截断 300 字符，防止超长输入打爆磁盘

## 5. UI 可视化

侧边栏新增"⏳ 调用侧防护"面板：

- 当前会话 ID
- 60 秒滑动窗口使用进度条（动态读取实际窗口大小）
- 4 个全局指标：总请求 / 放行 / 拦截 / 限流
- 最近 10 条审计日志（事件 + 命中规则 + prompt 摘要）

## 6. 压测验证

将阈值临时调为 3 次 / 30 秒进行人工压测：

| 步骤 | 操作 | 实际表现 |
|---|---|---|
| 1-3 | 连续 3 次正常提问 | 全部放行，进度条逐次推进至满 |
| 4 | 第 4 次提问 | 出现 ⏳ 限流卡片，未调用 LLM，"限流"指标 +1，审计日志写入 `rate_limited` |
| 5 | 等待 30 秒后再问 | 配额恢复，正常放行 |

压测完成后阈值已恢复至 20 次 / 60 秒。

## 7. 工程亮点（可写简历）

- 实现基于滑动窗口的会话级速率限制（默认 20 次/60 秒，可由环境变量配置），保护公开部署后的 API 配额免受滥用与意外消耗。
- 设计 JSONL 持久化审计日志，覆盖放行/拦截/限流/异常四类事件，支持事后追溯与合规审查。
- 与阶段 4 安全网关组合构成"双层防御 + 全链路审计"完整闭环，并通过侧边栏指标实时可视化。
- 引入 try/except 静默处理与 prompt 截断，确保日志层不会反向影响业务可用性与磁盘安全。

## 8. 面试可讲深度

- 为什么限流要放在安全网关之前？
  - 限流是最便宜的拒绝（O(1) 队列操作），早拒绝早省 CPU
- 为什么不用 Redis？
  - 当前为单进程 Streamlit 应用，内存级实现足够；上线多实例时再升级到 Redis + Lua 原子操作
- 审计日志为什么用 JSONL？
  - 流式追加友好，逐行可解析，下游工具链生态完善
- 怎么平衡"日志详细"与"隐私合规"？
  - prompt 截断 + 不记录用户身份信息 + `.gitignore` 排除日志目录

## 9. 后续可扩展

- 引入 IP 维度限流，session × IP 双键
- 接入 Redis 实现多实例共享配额
- 用 logrotate / Python `RotatingFileHandler` 做日志切割
- 把审计日志接入 Grafana / Kibana 做可视化大盘
- 加入 GitHub Actions：每次 push 跑评估 + 检查日志格式
