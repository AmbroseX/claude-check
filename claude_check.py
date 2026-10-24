#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI观潮 Claude 网络环境检测(命令行版)

查一下这台电脑的终端走的网络能不能安全地用 Claude:Claude 看到的 IP、地区、IP 类型、
IPv6 泄漏、DNS 泄漏、时区、语言、Cloudflare 人机验证、API 封没封、延迟和官方状态,
最后打 0~100 分并给改进建议。

网页版(在浏览器里测):https://aiguanchao.com/tools/claude-check
运行:
    curl -fsSL https://aiguanchao.com/agent/claude-check.py | python3
    python3 claude_check.py [--json] [--no-color] [--skip-api] [--skip-web]

只用 Python 自带的库(3.6 以上),不用装别的。会访问 claude.ai、api.anthropic.com(用假 key,
不带任何账号信息)、api6.ipify.org、edns.ip-api.com;查 IP 归属和官方状态走 aiguanchao.com,不保存。
思路参考 Panmax/claude-check,代码是重写的。
"""

import argparse
import json
import locale
import os
import platform
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"
SITE = "https://aiguanchao.com"
PAGE = SITE + "/tools/claude-check"
TRACE_URL = "https://claude.ai/cdn-cgi/trace"
LOGIN_URL = "https://claude.ai/login"
API_URL = "https://api.anthropic.com/v1/messages"
IPV6_URL = "https://api6.ipify.org?format=json"
DNS_URL = "https://edns.ip-api.com/json"  # 先 302 到随机子域名,逼着现解析
TRIES = 3
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
SCRIPT_UA = "aiguanchao-claude-check/" + VERSION

# Claude 不支持的地区(以 Anthropic 官方支持地区页为准)
UNSUPPORTED = {"CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU"}

# 国家 -> 常用语言;不在表里的不判语言
COUNTRY_LANG = {
    "US": ["en"], "GB": ["en"], "AU": ["en"], "CA": ["en", "fr"], "NZ": ["en"], "IE": ["en"],
    "JP": ["ja"], "KR": ["ko"], "DE": ["de"], "FR": ["fr"],
    "TW": ["zh"], "HK": ["zh", "en"], "SG": ["en", "zh"], "CN": ["zh"], "MO": ["zh", "pt"],
    "BR": ["pt"], "RU": ["ru"], "IN": ["en", "hi"],
    "NL": ["nl", "en"], "SE": ["sv", "en"], "NO": ["no", "nb", "nn", "en"],
    "DK": ["da", "en"], "FI": ["fi", "en"], "IT": ["it"],
    "ES": ["es"], "MX": ["es"], "AR": ["es"],
    "TH": ["th"], "VN": ["vi"], "PH": ["en", "fil"],
    "MY": ["ms", "en"], "ID": ["id"],
    "TR": ["tr"], "PL": ["pl"], "CZ": ["cs"],
}

ADVICE = {
    "proxy": "检查代理分流规则,让 claude.ai、anthropic.com 都走代理",
    "region": "换到 Claude 支持地区的节点(美国、日本、新加坡、台湾等)",
    "residential": "考虑换成住宅 IP / 原生 ISP 节点",
    "ipv6": "在系统网络设置里关掉 IPv6",
    "dns": "在代理软件里打开「远程 DNS 解析」(或 Fake-IP、TUN 模式)",
    "timezone": "把系统时区改成代理节点所在时区",
    "language": "把系统语言改成代理节点所在地区的常用语言",
    "wafBlocked": "当前 IP 被 Cloudflare 拦截,换个节点",
    "wafChallenge": "当前 IP 要过人机验证,不太干净,最好换个节点(浏览器里能直接打开 claude.ai 就不用管)",
    "apiBanned": "API 层面已被封,必须换 IP 节点",
}

BANDS = [(90, "极度纯净"), (75, "纯净"), (50, "良好"), (25, "中性"), (0, "危险")]
RISK_NAME = {"low": "低", "medium": "中", "high": "高", "critical": "极高"}
STATE_NAME = {"none": "正常", "minor": "部分异常", "major": "严重故障", "critical": "大面积故障",
              "maintenance": "维护中", "unknown": "暂时读不到"}


# ---------- 输出 ----------

class C:
    G, R, Y, B, DIM, BOLD, END = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m"

    @classmethod
    def off(cls):
        cls.G = cls.R = cls.Y = cls.B = cls.DIM = cls.BOLD = cls.END = ""


def setup_output(no_color):
    # Windows 老终端默认 GBK,换成 utf-8;不支持就算了(下面只用常见汉字和 ASCII 符号)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if no_color or not sys.stdout.isatty():
        C.off()
    elif platform.system() == "Windows":
        os.system("")  # 打开 Windows 10 终端的颜色支持


def mark(verdict):
    return {
        "pass": C.G + "[通过]" + C.END,
        "warn": C.Y + "[注意]" + C.END,
        "fail": C.R + "[不通过]" + C.END,
        "na": C.DIM + "[查不了]" + C.END,
    }[verdict]


# ---------- 网络 ----------

def http(method, url, body=None, headers=None, timeout=8):
    """发一次请求,返回 (状态码, 响应头, 内容, 毫秒);网络不通状态码为 None。会用终端的代理环境变量。"""
    h = {"User-Agent": SCRIPT_UA}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status, r.headers, r.read(), int((time.time() - t0) * 1000)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(), int((time.time() - t0) * 1000)
    except Exception:
        return None, None, b"", int((time.time() - t0) * 1000)


def get_json(url, timeout=8):
    code, _, body, _ = http("GET", url, timeout=timeout)
    if code != 200:
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def median(xs):
    if not xs:
        return None
    s = sorted(xs)
    return s[len(s) // 2]


# ---------- 各项检测 ----------

def check_proxy_env():
    names = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    # 代理地址里可能带账号密码,只显示主机和端口
    return {k: re.sub(r"//[^/@]*@", "//***@", os.environ[k]) for k in names if os.environ.get(k)}


def check_trace():
    """claude.ai 看到的 IP。连发 3 次取耗时中间值,第一次就失败不再试。"""
    out, times = None, []
    for _ in range(TRIES):
        code, _, body, ms = http("GET", TRACE_URL, timeout=6)
        if code != 200:
            break
        kv = dict(line.split("=", 1) for line in body.decode("utf-8", "replace").splitlines() if "=" in line)
        if not kv.get("ip"):
            break
        out = out or kv
        times.append(ms)
    return out, median(times)


def check_api():
    """假 key 发一条:401 = 能连上没被封,403 = 被封,别的 = 连不上。"""
    codes, times = [], []
    for _ in range(TRIES):
        code, _, _, ms = http("POST", API_URL, timeout=8, body={
            "model": "claude-haiku-4-5", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
            headers={"x-api-key": "sk-ant-network-check", "anthropic-version": "2023-06-01"})
        if code is None:
            break
        codes.append(code)
        times.append(ms)
    status = "banned" if 403 in codes else "ok" if 401 in codes else "error"
    return status, median(times)


def check_waf():
    """claude.ai 登录页:403 带 cf-mitigated: challenge = 要过人机验证,别的 403 = 被拦。"""
    code, headers, _, _ = http("GET", LOGIN_URL, timeout=8,
                               headers={"User-Agent": BROWSER_UA, "Accept": "text/html"})
    if code is None:
        return "unknown"
    if code == 403:
        return "challenge" if (headers.get("cf-mitigated") or "").lower() == "challenge" else "blocked"
    return "ok" if code < 400 else "unknown"


def check_ipv6():
    d = get_json(IPV6_URL, timeout=4)
    return (d or {}).get("ip")


def check_dns():
    """DNS 出口在哪:edns.ip-api.com 返回解析它的那台 DNS 服务器。"""
    d = get_json(DNS_URL, timeout=6)
    dns = (d or {}).get("dns") or {}
    if not dns.get("ip"):
        return {"status": "unknown"}
    geo = dns.get("geo", "")
    return {"status": "leaked" if geo.lower().startswith("china") else "ok", "ip": dns["ip"], "geo": geo}


def lookup(ips):
    """查 IP 归属(AI观潮后端,缓存 1 天,不保存)。返回 (归属, 访问本站的 IP, 本站额度用完没有)。"""
    if not ips:
        return {}, "", False
    code, _, body, _ = http("POST", SITE + "/api/claude-check", body={"ips": ips[:3]}, timeout=12)
    if code == 429:
        return {}, "", True
    if code != 200:
        return {}, "", False
    try:
        d = json.loads(body.decode("utf-8"))
    except ValueError:
        return {}, "", False
    return d.get("items") or {}, d.get("you") or "", bool(d.get("busy"))


def check_official():
    d = get_json(SITE + "/api/backend/public/status", timeout=6)
    for s in (d or {}).get("services") or []:
        if s.get("key") == "claude":
            return s.get("indicator")
    return None


def local_lang():
    if platform.system() == "Windows":
        try:
            import ctypes
            name = locale.windows_locale.get(ctypes.windll.kernel32.GetUserDefaultUILanguage())
            if name:
                return name
        except Exception:
            pass
    for k in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        v = os.environ.get(k)
        if v and v not in ("C", "POSIX") and not v.startswith("C."):
            return v
    try:
        return locale.getlocale()[0] or ""
    except Exception:
        return ""


# ---------- 打分(和网页版同一套扣分表,多了 DNS 和人机验证) ----------

def evaluate(x):
    if not x["trace_ip"]:
        return {"score": 0, "band": "危险", "risk": "critical",
                "items": [{"key": "trace", "verdict": "fail", "deduct": 100, "advice": "proxy"}]}
    items, flags = [{"key": "trace", "verdict": "pass", "deduct": 0}], {"red": 0, "yellow": 0}

    def add(key, verdict, deduct=0, advice=None, flag=None):
        items.append({"key": key, "verdict": verdict, "deduct": deduct, "advice": advice})
        if flag:
            flags[flag] += 1

    info = x["info"] if (x["info"] or {}).get("ok") else None
    if not info:
        add("region", "na")
        add("ip_type", "na")
    else:
        if info["country_code"] in UNSUPPORTED:
            add("region", "fail", 40, "region", "red")
        else:
            add("region", "pass")
        if info.get("hosting"):
            add("ip_type", "warn", 15, "residential", "yellow")
        elif info.get("proxy"):
            add("ip_type", "warn", 10, "residential", "yellow")
        else:
            add("ip_type", "pass")

    v6 = x["ipv6"]
    if not v6:
        add("ipv6", "pass")
    elif (v6.get("info") or {}).get("country_code") == "CN":
        add("ipv6", "fail", 20, "ipv6", "red")
    else:
        add("ipv6", "warn")

    dns = x["dns"]["status"]
    if dns == "leaked":
        add("dns", "fail", 20, "dns", "red")
    elif dns == "unknown":
        add("dns", "na", 5, None, "yellow")
    else:
        add("dns", "pass")

    if x["tz_match"] is None:
        add("timezone", "na", 0 if x["busy"] else 3, None, None if x["busy"] else "yellow")
    elif not x["tz_match"]:
        add("timezone", "fail", 15, "timezone", "red")
    else:
        add("timezone", "pass")

    expect = COUNTRY_LANG.get(info["country_code"]) if info else None
    lang = (x["lang"] or "").lower().replace("_", "-").split("-")[0]
    if not expect or not lang:
        add("language", "na")
    elif lang not in expect:
        add("language", "warn", 5, "language", "yellow")
    else:
        add("language", "pass")

    waf = x["waf"]
    if waf == "blocked":
        add("waf", "fail", 15, "wafBlocked", "red")
    elif waf == "challenge":
        add("waf", "warn", 8, "wafChallenge", "yellow")
    elif waf == "ok":
        add("waf", "pass")
    else:
        add("waf", "na")

    api = x["api"]
    if api == "banned":
        add("api", "fail", 15, "apiBanned", "red")
    elif api == "error":
        add("api", "warn", 5, "proxy", "yellow")
    elif api == "ok":
        add("api", "pass")
    else:
        add("api", "na")

    score = max(0, 100 - sum(i["deduct"] for i in items))
    red, yellow = flags["red"], flags["yellow"]
    risk = "critical" if red >= 2 else "high" if red == 1 else "medium" if yellow else "low"
    band = next(name for floor, name in BANDS if score >= floor)
    return {"score": score, "band": band, "risk": risk, "items": items}


# ---------- 汇总和输出 ----------

ITEM_NAME = {"trace": "Claude 看到的 IP", "region": "地区", "ip_type": "IP 类型", "ipv6": "IPv6",
             "dns": "DNS 泄漏", "timezone": "时区", "language": "语言", "waf": "Cloudflare 人机验证",
             "api": "API 封没封"}


def fmt_offset(sec):
    if sec is None:
        return "?"
    sign = "+" if sec >= 0 else "-"
    sec = abs(sec)
    return "UTC%s%d:%02d" % (sign, sec // 3600, sec % 3600 // 60)


def run(args, say):
    say(C.BOLD + "AI观潮 · Claude 网络环境检测 v" + VERSION + C.END)
    say(C.DIM + "网页版:" + PAGE + C.END + "\n")
    say("正在检测,大约 10~20 秒…")
    proxy_env = check_proxy_env()
    trace, trace_ms = check_trace()
    trace_ip = (trace or {}).get("ip")
    api, api_ms = ("skipped", None) if args.skip_api else check_api()
    waf = "skipped" if args.skip_web else check_waf()
    ipv6 = check_ipv6()
    dns = check_dns()
    official = check_official()
    ips = [ip for ip in [trace_ip, ipv6] if ip] if trace_ip else []
    items, you, busy = lookup(list(dict.fromkeys(ips)))
    info = items.get(trace_ip) if trace_ip else None
    local_off = time.localtime().tm_gmtoff
    tz_match = None
    if info and info.get("ok") and info.get("timezone"):
        tz_match = local_off == info.get("offset")
    x = {
        "trace_ip": trace_ip, "colo": (trace or {}).get("colo"), "info": info,
        "ipv6": {"ip": ipv6, "info": items.get(ipv6)} if ipv6 else None,
        "dns": dns, "tz_match": tz_match, "local_offset": local_off, "lang": local_lang(),
        "waf": waf, "api": api, "busy": busy, "proxy_env": proxy_env, "you": you,
        "latency_ms": {"claude_ai": trace_ms, "api": api_ms}, "official": official,
    }
    return x, evaluate(x)


def detail(key, verdict, x):
    info = x["info"] if (x["info"] or {}).get("ok") else None
    if key == "trace":
        return "%s(Cloudflare 节点 %s)" % (x["trace_ip"], x["colo"] or "?") if x["trace_ip"] \
            else "打不开 claude.ai:没走代理,或代理没覆盖 claude.ai"
    if key in ("region", "ip_type") and not info:
        return "IP 归属查不到" + (",AI观潮查询额度暂时用完,稍后再试" if x["busy"] else "")
    if key == "region":
        return ("%s 不在 Claude 支持的地区" if verdict == "fail" else "%s") % (info["country"] + " " + info["city"]).strip()
    if key == "ip_type":
        kind = "机房 IP" if info.get("hosting") else "代理 IP" if info.get("proxy") else "普通宽带 IP"
        return "%s · %s" % (kind, info.get("isp") or info.get("as") or "?")
    if key == "ipv6":
        if not x["ipv6"]:
            return "没有 IPv6"
        where = (x["ipv6"].get("info") or {}).get("country") or "?"
        return "IPv6 走了国内线路 %s" % x["ipv6"]["ip"] if verdict == "fail" \
            else "有 IPv6 %s(%s),不在国内,不扣分" % (x["ipv6"]["ip"], where)
    if key == "dns":
        d = x["dns"]
        return "查不到 DNS 出口" if d["status"] == "unknown" else "DNS 出口 %s(%s)" % (d["ip"], d["geo"])
    if key == "timezone":
        return "本机 %s,IP 所在地 %s %s" % (fmt_offset(x["local_offset"]), (info or {}).get("timezone", "?"),
                                          fmt_offset((info or {}).get("offset")) if info else "")
    if key == "language":
        expect = COUNTRY_LANG.get(info["country_code"]) if info else None
        return "本机 %s,当地常用 %s" % (x["lang"] or "?", " / ".join(expect)) if expect else "这个地区不判语言"
    if key == "waf":
        return {"ok": "能直接打开 claude.ai", "challenge": "要过人机验证",
                "blocked": "被 Cloudflare 拦截", "skipped": "跳过了"}.get(x["waf"], "连不上 claude.ai 登录页")
    if key == "api":
        return {"ok": "能连上 API(返回 401,说明没被封)", "banned": "API 返回 403,这个 IP 被封了",
                "skipped": "跳过了"}.get(x["api"], "连不上 api.anthropic.com")
    return ""


def print_report(x, r, say):
    say("")
    if x["proxy_env"]:
        say(C.DIM + "终端代理环境变量:" + ", ".join("%s=%s" % kv for kv in x["proxy_env"].items()) + C.END)
    else:
        say(C.DIM + "终端没设代理环境变量(用 TUN / 全局模式的话正常)" + C.END)
    say("")
    for it in r["items"]:
        minus = (C.R + "  -%d" % it["deduct"] + C.END) if it["deduct"] else ""
        say("%s %s%s" % (mark(it["verdict"]), C.BOLD + ITEM_NAME[it["key"]] + C.END, minus))
        say("       " + detail(it["key"], it["verdict"], x))
    lat = x["latency_ms"]
    ms = lambda v: "测不出" if v is None else "%d ms" % v
    say("")
    say("延迟:claude.ai %s,API %s" % (ms(lat["claude_ai"]), ms(lat["api"])))
    if x["official"]:
        say("Claude 官方状态:%s(详情 %s/status)" % (STATE_NAME.get(x["official"], x["official"]), SITE))
    if x["you"]:
        say(C.DIM + "你访问 AI观潮 用的 IP:%s(和 Claude 看到的不一样是正常的,不扣分)" % x["you"] + C.END)

    color = C.G if r["score"] >= 75 else C.Y if r["score"] >= 50 else C.R
    filled = r["score"] // 5
    say("")
    say("得分 %s%s%d%s  %s  [%s%s]  风险:%s" % (C.BOLD, color, r["score"], C.END, r["band"],
                                          color + "#" * filled + C.END, C.DIM + "-" * (20 - filled) + C.END,
                                          RISK_NAME[r["risk"]]))
    advice = []
    for it in r["items"]:
        if it.get("advice") and it["advice"] not in advice:
            advice.append(it["advice"])
    say("")
    if advice:
        say(C.BOLD + "改进建议" + C.END)
        for i, a in enumerate(advice, 1):
            say("  %d. %s" % (i, ADVICE[a]))
    else:
        say("没有要改的,保持现在的设置就好。")
    say("")
    say(C.DIM + "终端和浏览器走的线路可能不一样,浏览器里也测一次:" + PAGE + C.END)


def main():
    p = argparse.ArgumentParser(description="AI观潮 Claude 网络环境检测(命令行版) " + PAGE)
    p.add_argument("--json", action="store_true", help="输出 JSON")
    p.add_argument("--no-color", action="store_true", help="不要彩色输出")
    p.add_argument("--skip-api", action="store_true", help="不测 API 封没封")
    p.add_argument("--skip-web", action="store_true", help="不测 Cloudflare 人机验证")
    args = p.parse_args()
    setup_output(args.no_color or args.json)
    say = (lambda s: None) if args.json else print
    try:
        x, r = run(args, say)
    except KeyboardInterrupt:
        sys.exit(130)
    if args.json:
        print(json.dumps({"version": VERSION, "result": r, "checks": x}, ensure_ascii=False, indent=2))
    else:
        print_report(x, r, say)


if __name__ == "__main__":
    main()
