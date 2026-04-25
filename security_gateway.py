"""
LLM Security Advisor — 应用层安全网关模块
==========================================
负责对用户输入做规则检测，识别 Prompt Injection / Jailbreak /
System Prompt Leak / Encoded Injection / Out-of-Scope 五类风险。

被两处复用：
  1. app.py            —— 真实运行时的前置网关
  2. tests/run_eval.py —— 自动化评估脚本

模块化原因：避免评估脚本启动时把 Streamlit 一起拉起来。
"""

import re

# ---- 高风险规则：命中即拦截 ----
HIGH_RISK_PATTERNS = [
    {
        "name": "指令覆盖（中文）",
        "category": "Prompt Injection",
        "pattern": re.compile(r"忽略.{0,10}(之前|前面|上面|所有|原|先前).{0,10}(指令|提示|规则|设定|要求)"),
    },
    {
        "name": "指令覆盖（英文）",
        "category": "Prompt Injection",
        "pattern": re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|earlier|foregoing)\s+(\w+\s+){0,3}(instructions?|prompts?|rules?|directives?)", re.IGNORECASE),
    },
    {
        "name": "系统提示提取（中文）",
        "category": "System Prompt Leak",
        "pattern": re.compile(r"(输出|展示|告诉我|显示|重复|复述|完整).{0,15}(system\s*prompt|系统提示|系统指令|你的指令|原始指令|内部规则|隐藏.{0,3}提示)", re.IGNORECASE),
    },
    {
        "name": "系统提示提取（英文）",
        "category": "System Prompt Leak",
        "pattern": re.compile(r"(repeat|reveal|show|print|output|expose|tell\s+me).{0,25}(system\s*prompt|original\s+instructions?|hidden\s+(prompt|instructions?)|your\s+instructions?)", re.IGNORECASE),
    },
    {
        "name": "角色越狱（DAN / 开发者模式）",
        "category": "Jailbreak",
        "pattern": re.compile(r"\b(DAN|Do\s*Anything\s*Now|Developer\s*Mode|jailbreak)\b|越狱模式|无视所有.{0,5}规则|没有限制的(助手|模式|AI)", re.IGNORECASE),
    },
    {
        "name": "角色覆盖",
        "category": "Jailbreak",
        "pattern": re.compile(r"(从现在开始|从此).{0,15}(你|你是|你扮演|你将).{0,20}(不再是|不是|是另一个|扮演|变成)"),
    },
    {
        "name": "Base64 可疑长串",
        "category": "Encoded Injection",
        "pattern": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    },
    {
        "name": "解码并执行",
        "category": "Encoded Injection",
        "pattern": re.compile(r"(解码.{0,5}(并|然后|后).{0,5}(执行|回答|输出|按.{0,3}做)|decode.{0,20}(and|then).{0,5}(execute|run|follow|answer|do))", re.IGNORECASE),
    },
]

# ---- 业务越界关键词：本项目只回答 Web 安全 ----
OFFTOPIC_KEYWORDS = [
    "家常菜", "菜谱", "好吃的", "做饭", "美食", "餐厅",
    "好玩", "旅游", "景点", "哪里玩", "约会",
    "写诗", "诗歌", "现代诗", "散文", "小说",
    "相对论", "物理学", "化学", "数学题", "微积分",
    "贪吃蛇", "小游戏", "写一个游戏", "游戏代码",
    "天气", "股票", "理财", "明星", "电影推荐", "歌曲",
]

# ---- 安全领域白名单：包含这些词，即使含越界词也放行 ----
SECURITY_KEYWORDS = [
    "xss", "csrf", "sqli", "sql 注入", "sql注入", "注入", "漏洞", "渗透", "攻击", "防御",
    "认证", "session", "cookie", "jwt", "oauth", "鉴权",
    "上传", "文件包含", "lfi", "rfi", "webshell", "路径穿越",
    "prompt injection", "提示词注入", "越狱", "llm", "ai 安全", "ai安全",
    "owasp", "csp", "burp", "nmap", "信息搜集", "暴力破解",
    "安全", "加密", "解密", "哈希", "签名", "证书",
]


def detect_injection(text: str) -> dict:
    """应用层安全网关：返回风险等级与命中规则。

    Returns:
        dict: {"risk": "high"|"safe", "category": str, "rule": str, "reason": str}
    """
    if not text or not text.strip():
        return {"risk": "safe", "category": "", "rule": "", "reason": ""}

    # 1) 高风险：注入 / 越狱 / 系统提示提取 / 编码混淆
    for rule in HIGH_RISK_PATTERNS:
        if rule["pattern"].search(text):
            return {
                "risk": "high",
                "category": rule["category"],
                "rule": rule["name"],
                "reason": f"命中高风险规则「{rule['name']}」（{rule['category']}）",
            }

    # 2) 业务越界：含越界关键词且不含任何安全关键词
    text_lower = text.lower()
    has_security_kw = any(kw in text_lower for kw in SECURITY_KEYWORDS)
    matched_offtopic = next((kw for kw in OFFTOPIC_KEYWORDS if kw in text), None)
    if matched_offtopic and not has_security_kw:
        return {
            "risk": "high",
            "category": "Out-of-Scope",
            "rule": "业务越界",
            "reason": f"输入包含非安全领域关键词「{matched_offtopic}」，本系统仅回答 Web 安全相关问题。",
        }

    return {"risk": "safe", "category": "", "rule": "", "reason": ""}
