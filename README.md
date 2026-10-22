# claude-check · Claude 网络环境检测

查一下你的网络能不能安全地用 Claude:Claude 看到的 IP、地区、IP 类型(机房 / 住宅)、WebRTC / IPv6 / DNS 泄漏、时区、语言、Cloudflare 人机验证、API 有没有被封、延迟和官方状态,最后打 0~100 分并给改进建议。

**不想装东西?直接用网页版:<https://aiguanchao.com/tools/claude-check>**(在浏览器里测,点一下就出结果)

## 命令行版

只用 Python 自带的库(3.6 以上),不用装别的。

```bash
# 一行运行
curl -fsSL https://aiguanchao.com/agent/claude-check.py | python3

# 或者先下载、看一眼再运行
curl -fsSLO https://aiguanchao.com/agent/claude-check.py
python3 claude-check.py
```

Windows PowerShell:

```powershell
irm https://aiguanchao.com/agent/claude-check.py -OutFile claude-check.py; python claude-check.py
```

也可以直接用本仓库的 `claude_check.py`。

| 参数 | 作用 |
|---|---|
| `--skip-api` | 不测 api.anthropic.com |
| `--skip-web` | 不测 claude.ai 网页的人机验证 |
| `--json` | 输出 JSON,方便脚本处理 |
| `--no-color` | 不带颜色 |

## 会访问哪些地址

- `claude.ai/cdn-cgi/trace`、`claude.ai/login`:Claude 看到的 IP、有没有人机验证
- `api.anthropic.com`:用假 key 发一个请求,只看回 401 还是 403,不带任何账号信息
- `api6.ipify.org`:有没有 IPv6
- `edns.ip-api.com`:DNS 请求从哪出去
- `aiguanchao.com`:查 IP 归属、Claude 官方状态,不保存结果

## 怎么看结果

- 90 分以上很干净;50 分以下建议先按提示改再用
- 红灯(地区不支持、泄漏、时区不一致、API 被封)比黄灯(机房 IP、语言不一致)严重得多

## 说明

检测思路参考了 [Panmax/claude-check](https://github.com/Panmax/claude-check),代码是重写的。

更多 AI 工具和每日 AI 新闻:[AI观潮](https://aiguanchao.com)

MIT License
