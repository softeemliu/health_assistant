"""
health_assistant.profile — 用户目录梳理（点目录 / AppData / 大文件）

为什么单独一层：
  用户目录是"体积最大、最没人管"的地方 —— 一堆 .xxx 工具数据目录（各种 AI CLI、
  编辑器、包管理器各占一份），加上 AppData 三兄弟（Roaming / Local / LocalLow）。
  这些目录不属于任何"已安装程序"的安装目录，注册表里也查不到，因此
  leftover.py 那套"有没有主"的判定对它们完全不适用。

本模块只做三件事，全部只读：
  1. 把它们逐个量出来（体积 / 文件数 / 最近写入），带时间预算，扫不完就标"≥"。
  2. 分类 + 风险分级：缓存可清 / 数据留神 / 凭据密钥别动。
  3. 找"藏在点文件里的明文凭据"（.git-credentials / .npmrc / .netrc / .pypirc ...）
     —— 这是用户目录里最该被梳理的安全问题。

不做的事：不删除。清理入口统一在 CLI 的 clean 里，且走回收站。
"""

from __future__ import annotations

import json
import os
import re
import time
from concurrent import futures

__all__ = [
    "scan", "dir_stats", "cache_candidates", "secret_files", "largest_files",
    "empty_dots", "empty_dot_targets", "empty_user_dirs", "USER_EMPTY_ROOTS",
    "classify_dot", "classify_appdata", "DOT_RULES", "APPDATA_RULES",
    "format_size", "HOME",
]

HOME = os.environ.get("USERPROFILE") or os.path.expanduser("~")
APPDATA = os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")
LOCAL = os.environ.get("LOCALAPPDATA") or os.path.join(HOME, "AppData", "Local")
LOCALLOW = os.path.join(HOME, "AppData", "LocalLow")

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# home 下这些是系统 junction / 兼容性壳子，指向别处，扫了会重复计数甚至绕圈
HOME_JUNK = {
    "application data", "local settings", "my documents", "nethood", "printhood",
    "recent", "sendto", "templates", "「开始」菜单", "start menu", "cookies",
    "3d objects", "contacts", "favorites", "links", "saved games", "searches",
    "appdata", "ntuser.dat", "ntuser.ini", "desktop.ini",
}
HOME_DIR_SKIP_PREFIX = ("ntuser.dat",)


# ───────────────────────────── 体积统计 ─────────────────────────────

def _is_reparse(st):
    try:
        return bool(st.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def dir_stats(path, budget=0.6, max_files=60000, deadline=None):
    """统计目录体积/文件数/最近写入。跳过 junction（避免重复计数与死循环）。

    deadline 是"全局截止时刻"，与单项 budget 取较小值 —— 这样并行时所有线程
    会一起按时收手，不会出现某个大目录把整轮巡检拖过头。
    返回 {size, files, newest, truncated}。truncated=True 时 size 是下限。
    """
    total = files = 0
    newest = 0.0
    truncated = False
    started = time.time()
    stop_at = started + budget
    if deadline is not None:
        stop_at = min(stop_at, deadline)
    stack = [path]
    while stack:
        if time.time() > stop_at or files >= max_files:
            truncated = True
            break
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                    if e.is_dir(follow_symlinks=False):
                        if not _is_reparse(st):
                            stack.append(e.path)
                    else:
                        total += st.st_size
                        files += 1
                        if files >= max_files:
                            truncated = True
                            break
        except OSError:
            continue
    return {"size": total, "files": files, "newest": newest, "truncated": truncated}


def format_size(n):
    try:
        n = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            return f"{int(n)}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


# ───────────────────────────── 分类规则 ─────────────────────────────
#
# (说明, 类别, 风险)
#   类别: cache 缓存 / model 模型权重 / tool 工具数据 / secret 凭据 / other 未识别
#   风险: safe 可清 / repeat 删了要重下或重新登录 / keep 别动 / secret 明文凭据

DOT_RULES = {
    ".ssh": ("SSH 私钥与 known_hosts", "secret", "keep"),
    ".gnupg": ("GPG 密钥环", "secret", "keep"),
    ".gitconfig": ("Git 全局配置（身份 / 别名 / 凭据助手）", "tool", "keep"),
    ".git-credentials": ("Git 明文账号密码（credential.helper=store）", "secret", "secret"),
    ".netrc": ("FTP/HTTP 自动登录口令", "secret", "secret"),
    ".pypirc": ("PyPI 上传口令", "secret", "secret"),
    ".npmrc": ("npm 源与发布 token", "secret", "secret"),
    ".zshrc": ("shell 启动脚本", "tool", "keep"),
    ".cache": ("通用缓存", "cache", "safe"),
    ".npm": ("npm 全局包 + 下载缓存", "cache", "repeat"),
    ".yarn": ("yarn 缓存", "cache", "safe"),
    ".cargo": ("Rust 包缓存", "cache", "safe"),
    ".gradle": ("Gradle 缓存", "cache", "safe"),
    ".m2": ("Maven 本地仓库", "cache", "repeat"),
    ".nuget": ("NuGet 包缓存", "cache", "safe"),
    ".conda": ("Conda 环境与缓存", "cache", "repeat"),
    ".uv": ("uv 缓存", "cache", "safe"),
    ".local": ("pipx / 用户级 Python 安装", "tool", "repeat"),
    ".ollama": ("Ollama 模型权重", "model", "repeat"),
    ".modelscope": ("ModelScope 模型缓存", "model", "repeat"),
    ".ollama_manager": ("Ollama Manager 配置", "tool", "repeat"),
    ".vscode": ("VS Code 扩展 / 缓存", "tool", "repeat"),
    ".vscode-shared": ("VS Code 共享存储", "tool", "repeat"),
    ".android": ("Android SDK/AVD 数据", "tool", "repeat"),
    ".dotnet": ("dotnet 本地工具与 NuGet 缓存", "cache", "repeat"),
    ".omnisharp": ("OmniSharp(C#) 缓存", "cache", "safe"),
    ".templateengine": ("dotnet new 模板缓存", "cache", "safe"),
    ".claude": ("Claude Code 配置与历史会话", "tool", "repeat"),
    ".claude.json": ("Claude Code 全局配置（可能含 token）", "secret", "secret"),
    ".codex": ("Codex CLI 配置与缓存", "tool", "repeat"),
    ".gemini": ("Gemini CLI 配置与缓存", "tool", "repeat"),
    ".copilot": ("Copilot 配置与缓存", "tool", "repeat"),
    ".cursor": ("Cursor 编辑器数据", "tool", "repeat"),
    ".continue": ("Continue 插件配置", "tool", "repeat"),
    ".codebuddy": ("CodeBuddy 工具数据", "tool", "repeat"),
    ".codegraph": ("CodeGraph 索引缓存", "cache", "safe"),
    ".agent-browser": ("Agent 浏览器运行时（含 Chromium）", "cache", "repeat"),
    ".agentscope-runtime": ("AgentScope 运行时缓存", "cache", "safe"),
    ".workbuddy": ("WorkBuddy 工作数据", "tool", "repeat"),
    ".workbuddy-key-fallback": ("WorkBuddy 备用密钥文件", "secret", "secret"),
    ".qwenpaw": ("QwenPaw 工具数据", "tool", "repeat"),
    ".qwenpaw.secret": ("QwenPaw 密钥文件", "secret", "secret"),
    ".qwen-agent": ("Qwen Agent 数据", "tool", "repeat"),
    ".kimi-code": ("Kimi Code 数据", "tool", "repeat"),
    ".kimi-work": ("Kimi Work 数据", "tool", "repeat"),
    ".kimi-webbridge": ("Kimi 浏览器桥接", "tool", "repeat"),
    ".lark-cli": ("飞书 CLI 数据", "tool", "repeat"),
    ".openclaw": ("OpenClaw 数据", "tool", "repeat"),
    ".openclaude": ("OpenClaude 数据", "tool", "repeat"),
    ".grok": ("Grok CLI 数据", "tool", "repeat"),
    ".mimo": ("MiMo 数据", "tool", "repeat"),
    ".dsh": ("dsh(DeepSeek Harness) 数据", "tool", "repeat"),
    ".factory": ("Factory 数据", "tool", "repeat"),
    ".pi": ("Pi 数据", "tool", "repeat"),
    ".orca": ("Orca 数据", "tool", "repeat"),
    ".qoder": ("Qoder 编辑器数据", "tool", "repeat"),
    ".qoder-cn": ("Qoder 中文版数据", "tool", "repeat"),
    ".trae-cn": ("Trae 编辑器数据", "tool", "repeat"),
    ".commandcode": ("CommandCode 数据", "tool", "repeat"),
    ".cc-switch": ("CC Switch 配置文件", "tool", "repeat"),
    ".lobbywork": ("LobbyWork 数据", "tool", "repeat"),
    ".icube-remote-ssh": ("iCube 远程 SSH 会话", "tool", "repeat"),
    ".ai_completion": ("AI 补全插件缓存", "cache", "safe"),
    ".nosqlbooster4mongo": ("NoSQLBooster 配置与连接", "tool", "repeat"),
    ".sheetagent": ("SheetAgent 缓存", "cache", "safe"),
    ".omp": ("OMP 配置", "tool", "repeat"),
    ".venv-html-to-docx": ("一次性 Python 虚拟环境", "cache", "repeat"),
    ".Ld9VirtualBox": ("虚拟化组件数据", "tool", "review"),
}

# 关键词兜底：表里没有的新工具按名字猜类别
_CACHE_WORDS = ("cache", "tmp", "temp", "logs", "log", "cache2", "build",
                "dist", "compiled", "index")
_MODEL_WORDS = ("model", "models", "weights", "gguf", "checkpoint", "hf")
_TOOL_WORDS = ("code", "cli", "agent", "config", "cfg", "cursor", "claude",
               "gpt", "llm", "ai", "chat", "assistant", "editor", "ide")


def classify_dot(name):
    """点文件/点目录 → (说明, 类别, 风险)。"""
    low = name.lower()
    hit = DOT_RULES.get(low)
    if hit:
        return hit
    bare = low.lstrip(".")
    if bare in ("env", "docker", "kube", "aws", "azure") or "credentials" in bare:
        return ("凭据/密钥相关目录", "secret", "secret")
    if any(w in bare for w in _MODEL_WORDS):
        return ("模型权重或缓存", "model", "repeat")
    if any(w == bare or bare.endswith(w) for w in ("cache", "caches")):
        return ("工具缓存", "cache", "safe")
    if any(w in bare for w in _CACHE_WORDS):
        return ("疑似缓存（名字含 cache/log/build）", "cache", "review")
    if any(w in bare for w in _TOOL_WORDS):
        return ("工具数据目录（未登记具体用途）", "tool", "review")
    return ("未识别", "other", "review")


APPDATA_RULES = {
    # Local / Roaming / LocalLow 同名规则共用
    "temp": ("临时文件（Windows 与各程序共用，可清内容但别删目录）", "cache", "review"),
    "tmp": ("临时文件", "cache", "review"),
    "temporary internet files": ("IE/系统缓存", "cache", "safe"),
    "crashdumps": ("崩溃转储", "cache", "safe"),
    "d3dscache": ("DirectX 着色器缓存", "cache", "safe"),
    "iconcache.db": ("图标缓存（可让系统重建）", "cache", "safe"),
    "npm-cache": ("npm 下载缓存", "cache", "safe"),
    "npm": ("npm 全局包", "cache", "repeat"),
    "pip": ("pip 下载缓存", "cache", "safe"),
    "uv": ("uv 缓存", "cache", "safe"),
    "yarn": ("yarn 缓存", "cache", "safe"),
    "hermes": ("Hermes JS 引擎缓存", "cache", "safe"),
    "ms-playwright": ("Playwright 浏览器内核", "cache", "repeat"),
    "electron": ("Electron 运行时缓存", "cache", "repeat"),
    "cmaketools": ("CMake 工具缓存", "cache", "safe"),
    "nuget": ("NuGet 包缓存", "cache", "safe"),
    "package cache": ("VS/安装器包缓存", "cache", "repeat"),
    "downloaded installations": ("安装包残留", "cache", "safe"),
    "squirreltemp": ("Squirrel 更新临时文件", "cache", "safe"),
    "webcache": ("Web 缓存", "cache", "safe"),
    "google": ("Chrome 配置/缓存/书签", "tool", "repeat"),
    "microsoft": ("系统与 Office 数据", "tool", "keep"),
    "packages": ("UWP 应用数据", "tool", "keep"),
    "programs": ("用户级程序安装目录（不是缓存）", "tool", "keep"),
    "connecteddevicesplatform": ("设备平台缓存", "cache", "safe"),
    "peerdistrepub": ("对等分发缓存", "cache", "safe"),
    "projfs": ("投影文件系统缓存", "cache", "safe"),
    "publishers": ("ClickOnce 发布者数据", "tool", "keep"),
    "placeholderTileLogoFolder": ("磁贴缓存", "cache", "safe"),
    "application data": ("指向 Local 的 junction", "other", "keep"),
    "history": ("IE 历史记录", "cache", "safe"),
    "assembly": (".NET 程序集缓存", "cache", "repeat"),
    "temp": ("临时文件", "cache", "review"),
}


def classify_appdata(name, root_label=""):
    low = name.lower()
    hit = APPDATA_RULES.get(low)
    if hit:
        return hit
    if any(w in low for w in ("cache", "temp", "log", "crash", "dump", "update")):
        return ("疑似缓存/日志（名字含 cache/temp/log/update）", "cache", "review")
    if any(w in low for w in _MODEL_WORDS):
        return ("模型或权重数据", "model", "repeat")
    return ("程序数据目录", "tool", "review")


# ───────────────────────────── 明文凭据排查 ─────────────────────────────

# (相对 home 的路径, 名称, 正则, 取值组)
_SECRET_PROBES = [
    (".git-credentials", "Git 明文凭据（credential.helper=store）",
     re.compile(r"(https?://[^\s:@/]+):([^\s@/]+)@"), 2),
    (".npmrc", "npm 发布 token", re.compile(r"_authToken\s*=\s*(\S+)"), 1),
    (".netrc", "FTP/HTTP 自动登录口令", re.compile(r"password\s+(\S+)"), 1),
    ("_netrc", "FTP/HTTP 自动登录口令", re.compile(r"password\s+(\S+)"), 1),
    (".pypirc", "PyPI 上传口令", re.compile(r"password\s*=\s*(\S+)"), 1),
    (".docker/config.json", "Docker registry 认证（base64）",
     re.compile(r"\"auth\"\s*:\s*\"([^\"]+)\""), 1),
    (".kube/config", "Kubernetes token/证书", re.compile(r"token\s*:\s*(\S+)"), 1),
    (".aws/credentials", "AWS 密钥", re.compile(r"aws_secret_access_key\s*=\s*(\S+)"), 1),
    (".qwenpaw.secret", "工具密钥文件", re.compile(r"(\S{8,})"), 1),
    (".workbuddy-key-fallback", "工具备用密钥", re.compile(r"(\S{8,})"), 1),
]

_SSH_KEY_FILES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")

# 点目录里"文件名看起来像凭据"的文件 → 再看内容里有没有真凭据
_TOKEN_NAME_RE = re.compile(
    r"(?i)(credential|token|secret|auth|api[-_]?key|apikey|passw|session|\.key$|\.pem$|\.env)")
_TOKEN_VALUE_RES = [
    ("OpenAI/Anthropic 风格 sk- key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("JWT 令牌", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("JSON 里的 access_token / api_key",
     re.compile(r"\"(?:access_token|refresh_token|api_key|apikey|token)\"\s*:\s*\"([^\"\n]{12,})\"")),
    ("AWS secret", re.compile(r"aws_secret_access_key\s*[=:]\s*\"?([A-Za-z0-9/+=]{20,})")),
]
_TOKEN_HUNT_SKIP = {
    "node_modules", ".git", "cache", "cachedata", "cache2", "extensions", "logs",
    "log", "blob_storage", "gpucache", "code cache", "dawncache", "temp", "tmp",
    "crashpad", "service worker", "cachestorage", "workspace storage",
}


def _token_hunt(roots, depth=2, budget=3.0, max_files=4000, reveal=True):
    """在点目录里按文件名筛出疑似凭据文件，再按内容确认真有 token。"""
    found = []
    started = time.time()
    inspected = 0
    seen = set()

    for root in roots:
        if not os.path.isdir(root):
            continue
        base = root.rstrip("\\").count("\\")
        for cur, subdirs, files in os.walk(root):
            if time.time() - started > budget or inspected >= max_files:
                return found
            if cur.rstrip("\\").count("\\") - base >= depth:
                subdirs[:] = []
            subdirs[:] = [d for d in subdirs if d.lower() not in _TOKEN_HUNT_SKIP
                          and not d.startswith("$")]
            for f in files:
                if not _TOKEN_NAME_RE.search(f):
                    continue
                path = os.path.join(cur, f)
                if path in seen:
                    continue
                seen.add(path)
                inspected += 1
                try:
                    if os.path.getsize(path) > 262144:
                        continue
                    text = open(path, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for label, rx in _TOKEN_VALUE_RES:
                    hits = rx.findall(text)
                    if not hits:
                        continue
                    sample = hits[0] if isinstance(hits[0], str) else str(hits[0])
                    found.append({
                        "path": path, "label": label, "count": len(hits),
                        "bytes": os.path.getsize(path),
                        "mtime": time.strftime("%Y-%m-%d",
                                               time.localtime(os.path.getmtime(path))),
                        "sample": sample[:48] if reveal else "",
                    })
                    break
                if inspected >= max_files or time.time() - started > budget:
                    return found
    return found


def secret_files(reveal=True, max_read=262144, hunt=True):
    """找出用户目录里"明文保存着凭据"的文件。只读，默认不显示值。"""
    out = []

    for rel, label, rx, grp in _SECRET_PROBES:
        path = os.path.join(HOME, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(max_read)
        except OSError:
            continue
        hits = rx.findall(text)
        if not hits:
            continue
        first = hits[0]
        val = first if isinstance(first, str) else (first[grp - 1] if len(first) >= grp else "")
        out.append({
            "path": path, "label": label, "count": len(hits),
            "bytes": os.path.getsize(path),
            "mtime": time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path))),
            "sample": val[:48] if reveal else "",
        })

    # .gitconfig 里若用 store 助手，等于把密码明文放在 .git-credentials
    gc = os.path.join(HOME, ".gitconfig")
    if os.path.isfile(gc):
        try:
            text = open(gc, "r", encoding="utf-8", errors="replace").read(65536)
            m = re.search(r"(?i)helper\s*=\s*(\S+)", text)
            if m and ("store" in m.group(1).lower() or m.group(1).lower() in ("plaintext",)):
                out.append({
                    "path": gc, "label": f"Git 凭据助手 = {m.group(1)}（明文落盘）",
                    "count": 1, "bytes": os.path.getsize(gc),
                    "mtime": time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(gc))),
                    "sample": m.group(0) if reveal else "",
                })
        except OSError:
            pass

    # SSH 私钥：区分"有口令保护"和"裸私钥"
    for fn in _SSH_KEY_FILES:
        p = os.path.join(HOME, ".ssh", fn)
        if not os.path.isfile(p):
            continue
        try:
            head = open(p, "rb").read(4096).decode("utf-8", "replace")
        except OSError:
            continue
        encrypted = "ENCRYPTED" in head or "Proc-Type: 4,ENCRYPTED" in head
        out.append({
            "path": p,
            "label": "SSH 私钥" + ("（有口令保护）" if encrypted else "（无口令，任何拿到文件的人可直接用）"),
            "count": 1, "bytes": os.path.getsize(p),
            "mtime": time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(p))),
            "sample": "",
        })

    # 点目录里的 token / 凭据文件（各种 CLI 把登录态存成 json/key）
    if hunt:
        try:
            dots = [os.path.join(HOME, d) for d in os.listdir(HOME)
                    if d.startswith(".") and os.path.isdir(os.path.join(HOME, d))]
            extra = _token_hunt(dots, reveal=reveal)
        except Exception:
            extra = []
        have = {o["path"] for o in out}
        for f in extra:
            if f["path"] not in have:
                out.append(f)
                have.add(f["path"])

    out.sort(key=lambda x: x["path"].lower())
    return out


# ───────────────────────────── 大文件 ─────────────────────────────

def largest_files(dirs=None, min_mb=200, limit=15, budget=6.0):
    """在用户常用目录里找大文件（不递归过深，只进入 3 层）。"""
    dirs = dirs or [os.path.join(HOME, d) for d in
                    ("Downloads", "Desktop", "Documents", "Videos", "Pictures")]
    min_size = min_mb * 1048576
    found = []
    started = time.time()
    for root in dirs:
        if not os.path.isdir(root):
            continue
        base = root.rstrip("\\").count("\\")
        for cur, subdirs, files in os.walk(root):
            if time.time() - started > budget:
                found.sort(key=lambda x: -x["size"])
                return found[:limit]
            if cur.rstrip("\\").count("\\") - base >= 3:
                subdirs[:] = []
            subdirs[:] = [d for d in subdirs if not d.startswith(".")]
            for f in files:
                p = os.path.join(cur, f)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if st.st_size >= min_size:
                    found.append({"path": p, "size": st.st_size,
                                  "mtime": time.strftime("%Y-%m-%d",
                                                         time.localtime(st.st_mtime))})
    found.sort(key=lambda x: -x["size"])
    return found[:limit]


# ───────────────────────────── 主扫描 ─────────────────────────────

def _scan_entries(entries, deadline, per_budget=5.0, workers=8):
    """并行量一批目录的体积。

    目录遍历是 I/O 密集，线程能实打实并行（scandir 期间释放 GIL）。
    共享总时间预算：到点未完成的标 skipped，不让一个巨型目录拖垮整轮巡检。
    """
    return _scan_many({"all": entries}, deadline, per_budget, workers)["all"]


def _scan_many(groups, deadline, per_budget=5.0, workers=16):
    """一次喂给同一个线程池，量多批目录的体积。

    原来是 home / dot / Roaming / Local / LocalLow 分五批串行跑，
    每批都要等自己最慢那个目录（≈dir_seconds），五批相加就是 18s。
    合成一次派发后，总耗时≈所有目录里最慢的一个，而不是五批之和。
    """
    todo = []
    for gname, entries in (groups or {}).items():
        for path, name, kind in (entries or []):
            todo.append((gname, path, name, kind))
    out = {g: [] for g in (groups or {})}
    if not todo:
        return out
    with futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo)))) as pool:
        futs = {pool.submit(dir_stats, path, per_budget, 60000, deadline): (gname, path, name, kind)
                for gname, path, name, kind in todo}
        for fut in futures.as_completed(futs):
            gname, path, name, kind = futs[fut]
            try:
                st = fut.result()
            except Exception:
                st = {"size": 0, "files": 0, "newest": 0.0, "truncated": True}
            out[gname].append({"path": path, "name": name, "kind": kind, **st})
    return out


def scan(budget=8.0, top=15, min_mb=1.0, deep=False, dir_seconds=5.0):
    """用户目录全景梳理。budget 是总时间预算（秒），deep=True 时逐项不限时。

    dir_seconds 是单个目录的最长统计时间：目录遍历并行跑，所以整轮耗时
    基本等于"最大那个目录撞到 dir_seconds 的时间"，而不是所有目录相加。
    """
    started = time.time()
    deadline = started + budget
    result = {
        "home": HOME, "budget": budget, "elapsed": 0.0, "deep": deep,
        "home_dirs": [], "dot": [], "appdata": {}, "secrets": [],
        "big_files": [], "errors": [], "truncated": 0,
    }

    # ---- home 顶层普通目录（含 Downloads / Desktop 这类真正的数据） ----
    home_entries = []
    try:
        for e in os.scandir(HOME):
            if not e.is_dir(follow_symlinks=False):
                continue
            low = e.name.lower()
            if low in HOME_JUNK or any(low.startswith(p) for p in HOME_DIR_SKIP_PREFIX):
                continue
            if e.name.startswith("."):
                continue
            try:
                if _is_reparse(e.stat(follow_symlinks=False)):
                    continue
            except OSError:
                continue
            home_entries.append((e.path, e.name, "home"))
    except OSError as exc:
        result["errors"].append(f"读取用户目录失败: {exc}")

    # ---- 点目录 / 点文件 ----
    dot_entries = []
    try:
        for e in os.scandir(HOME):
            if not e.name.startswith("."):
                continue
            isdir = e.is_dir(follow_symlinks=False)
            dot_entries.append((e.path, e.name, "dotdir" if isdir else "dotfile"))
    except OSError as exc:
        result["errors"].append(f"读取点文件失败: {exc}")

    # ---- AppData 三个根 ----
    app_entries = {}
    for label, base in (("Roaming", APPDATA), ("Local", LOCAL), ("LocalLow", LOCALLOW)):
        rows = []
        if os.path.isdir(base):
            try:
                for e in os.scandir(base):
                    if not e.is_dir(follow_symlinks=False):
                        continue
                    try:
                        if _is_reparse(e.stat(follow_symlinks=False)):
                            continue
                    except OSError:
                        continue
                    rows.append((e.path, e.name, label))
            except OSError as exc:
                result["errors"].append(f"读取 {label} 失败: {exc}")
        app_entries[label] = rows

    # 并行扫描：所有条目共享一个总预算，单目录上限 dir_seconds（deep 时不限）
    per_budget = 600.0 if deep else float(dir_seconds)
    deadline = started + (3600.0 if deep else budget)

    # 五批目录一次派发，总耗时≈最慢那一项，而不是五批相加
    groups = {"home": home_entries, "dot": dot_entries}
    for label, rows in app_entries.items():
        groups[f"app_{label}"] = rows
    scanned = _scan_many(groups, deadline, per_budget, workers=16)
    result["home_dirs"] = scanned.get("home") or []
    result["dot"] = scanned.get("dot") or []
    for label in app_entries:
        result["appdata"][label] = scanned.get(f"app_{label}") or []

    # ---- 分类标注 ----
    def decorate(items, classifier, kind_name):
        for it in items:
            desc, cat, risk = classifier(it["name"])
            it["desc"], it["category"], it["risk"] = desc, cat, risk
            it["kind_label"] = kind_name
            it["idle_days"] = (int((time.time() - it["newest"]) / 86400)
                               if it["newest"] else 9999)
            it["last_active"] = (time.strftime("%Y-%m-%d", time.localtime(it["newest"]))
                                 if it["newest"] else "-")
            if it["truncated"]:
                result["truncated"] += 1

    decorate(result["home_dirs"], lambda n: ("用户目录内容", "data", "keep"), "home")
    decorate(result["dot"], classify_dot, "dot")
    for label, items in result["appdata"].items():
        decorate(items, lambda n, lab=label: classify_appdata(n, lab), label)

    # ---- 点目录里的明文凭据 ----
    try:
        result["secrets"] = secret_files(reveal=False)
    except Exception as exc:
        result["errors"].append(f"凭据排查失败: {exc}")

    # ---- 大文件 ----
    try:
        result["big_files"] = largest_files(min_mb=max(200, int(min_mb)))
    except Exception as exc:
        result["errors"].append(f"大文件扫描失败: {exc}")

    # ---- 汇总 ----
    def total_of(items):
        return sum(i["size"] for i in items)

    all_dot = result["dot"]
    all_app = [i for items in result["appdata"].values() for i in items]
    result["summary"] = {
        "home_dirs": len(result["home_dirs"]), "home_size": total_of(result["home_dirs"]),
        "dot_count": len(all_dot), "dot_size": total_of(all_dot),
        "dot_file_count": sum(1 for i in all_dot if i["kind"] == "dotfile"),
        "appdata_count": len(all_app), "appdata_size": total_of(all_app),
        "cache_size": total_of([i for i in all_dot + all_app if i["category"] == "cache"]),
        "model_size": total_of([i for i in all_dot + all_app if i["category"] == "model"]),
        "secret_files": len(result["secrets"]),
        "big_files": len(result["big_files"]),
        "big_files_size": total_of(result["big_files"]),
    }
    result["elapsed"] = round(time.time() - started, 1)
    return result


# ───────────────────────────── 清理候选 ─────────────────────────────

# 这些即使名字像缓存也不进清理候选：删了系统/IDE 会出问题，或本身就是凭据
_NEVER_TRASH = {
    "temp", "tmp", "package cache", "google", "microsoft", "packages", "programs",
    "publishers", "application data", "assembly", ".ssh", ".gnupg", ".gitconfig",
    ".claude.json", ".local", ".npm", ".ollama", ".modelscope",
}


def cache_candidates(result, min_mb=50, allow_repeat=False):
    """从 scan() 结果里挑出"可清"的缓存目录，转成 clean 用的候选结构。

    allow_repeat=False 时只给 safe（纯缓存，删了自动重建）；
    True 时连 repeat（删了要重新下载）一起给。
    """
    cands = []
    items = list(result.get("dot") or [])
    for rows in (result.get("appdata") or {}).values():
        items.extend(rows)

    for it in items:
        low = it["name"].lower()
        if low in _NEVER_TRASH:
            continue
        if it["category"] != "cache":
            continue
        if it["risk"] == "safe" or (allow_repeat and it["risk"] == "repeat"):
            pass
        else:
            continue
        if it["size"] / 1048576 < min_mb:
            continue
        cands.append({
            "path": it["path"], "name": it["name"], "size": it["size"],
            "files": it["files"], "idle_days": it["idle_days"],
            "category": "cache", "note": it["desc"],
            "confidence": "high" if it["risk"] == "safe" else "medium",
            "truncated": it["truncated"],
        })
    cands.sort(key=lambda c: -c["size"])
    return cands


def dump_json(result):
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)


# ─────────────────────── 空点目录（只读识别） ───────────────────────
#
# 空目录本身不占空间，但会让人误以为装着东西，也影响排查。
# 这里只负责"识别 + 分类"，删除入口在 CLI 的 clean --kind emptydot（走回收站）。

EMPTY_DOT_SKIP = {".git", ".hg", ".svn"}
EMPTY_CACHE_SEGS = {
    "tmp", "temp", "cache", "caches", "log", "logs",
    "download", "downloads", "thumbnail", "thumbnails", "spool", "staging",
}
# 以 .lock 结尾的目录是程序起的锁占位，删掉会让并发控制误判
EMPTY_LOCK_SUFFIX = ".lock"


def _seg_is_cache(seg):
    s = seg.lower().lstrip(".")
    if not s:
        return False
    return s in EMPTY_CACHE_SEGS or "cache" in s


def _tree_empty(path, deadline, max_nodes=6000):
    """判断是否是「空树」：递归下去没有任何文件。返回 (空?, 子目录数, 深度)。

    链接/junction 一律按"有内容"处理（保守），发现任何文件立刻返回。
    """
    dirs = 0
    deepest = 0
    seen = 0
    stack = [(path, 0)]
    while stack:
        if deadline and time.time() > deadline:
            return (False, dirs, deepest)
        cur, d = stack.pop()
        seen += 1
        if seen > max_nodes:
            return (False, dirs, deepest)
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        return (False, dirs, deepest)
                    if _is_reparse(st):
                        return (False, dirs, deepest)
                    if e.is_dir(follow_symlinks=False):
                        dirs += 1
                        if d + 1 > deepest:
                            deepest = d + 1
                        stack.append((e.path, d + 1))
                    else:
                        return (False, dirs, deepest)
        except OSError:
            return (False, dirs, deepest)
    return (True, dirs, deepest)


def _stamp(path):
    try:
        return time.strftime("%Y-%m-%d", time.localtime(
            os.stat(path, follow_symlinks=False).st_ctime))
    except OSError:
        return ""


def empty_dots(budget=6.0, max_depth=5, include_state=True):
    """找出用户目录下为空的点目录，以及点目录内部的空子目录。只读。

    分类：
      top    主目录第一层的空点目录（整棵树里没有任何文件）
      cache  路径中含 cache/tmp/temp/log/download 等词的空子目录 —— 可安全清
      state  其它空子目录 —— 工具状态目录，程序可能预期它存在，谨慎

    返回 {"top": [...], "nested": [...], "counts": {...},
          "truncated": bool, "elapsed": float}
    """
    started = time.time()
    deadline = started + max(1.0, budget)
    top, nested = [], []
    truncated = False

    try:
        entries = sorted(os.scandir(HOME), key=lambda e: e.name.lower())
    except OSError as exc:
        return {"top": [], "nested": [], "counts": {"top": 0, "cache": 0, "state": 0},
                "truncated": True, "elapsed": 0.0, "error": str(exc)}

    for e in entries:
        if time.time() > deadline:
            truncated = True
            break
        if not e.name.startswith("."):
            continue
        if e.name in HOME_JUNK or e.name.lower() in EMPTY_DOT_SKIP:
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        if _is_reparse(st) or not e.is_dir(follow_symlinks=False):
            continue

        empty, ndirs, deep = _tree_empty(e.path, deadline)
        if empty:
            top.append({"path": e.path, "rel": e.name, "dirs": ndirs,
                        "depth": deep, "created": _stamp(e.path)})
            continue

        base_depth = e.path.count(os.sep)
        try:
            for root, ds, fs in os.walk(e.path, followlinks=False):
                if time.time() > deadline:
                    truncated = True
                    break
                if root.count(os.sep) - base_depth >= max_depth:
                    ds[:] = []
                    continue
                keep = []
                for dn in ds:
                    try:
                        if not _is_reparse(os.stat(os.path.join(root, dn),
                                                   follow_symlinks=False)):
                            keep.append(dn)
                    except OSError:
                        pass
                ds[:] = keep
                if ds or fs:
                    continue
                if os.path.basename(root).lower().endswith(EMPTY_LOCK_SUFFIX):
                    continue
                rel = os.path.relpath(root, HOME)
                segs = rel.split(os.sep)[1:]
                kind = "cache" if any(_seg_is_cache(s) for s in segs) else "state"
                if kind == "state" and not include_state:
                    continue
                nested.append({"path": root, "rel": rel, "kind": kind,
                               "created": _stamp(root)})
        except OSError:
            pass

    nested.sort(key=lambda x: (x["kind"], x["rel"].lower()))
    counts = {
        "top": len(top),
        "cache": sum(1 for n in nested if n["kind"] == "cache"),
        "state": sum(1 for n in nested if n["kind"] == "state"),
    }
    return {"top": top, "nested": nested, "counts": counts,
            "truncated": truncated, "elapsed": round(time.time() - started, 1)}


def empty_dot_targets(result, include_state=False):
    """从 empty_dots() 结果里挑可清理的路径：顶层空点目录 + cache 类空子目录。

    父目录已在清单中时自动丢弃子目录（父删了子自然没了）。
    """
    paths = [t["path"] for t in (result.get("top") or [])]
    for n in result.get("nested") or []:
        if n["kind"] == "cache" or (include_state and n["kind"] == "state"):
            paths.append(n["path"])

    keep, seen = [], set()
    for p in sorted(paths, key=lambda x: x.count(os.sep)):
        low = os.path.abspath(p).lower()
        if any(low == s or low.startswith(s + os.sep) for s in seen):
            continue
        seen.add(low)
        keep.append(p)
    return keep


# ───────────────────── 用户文件夹里的空文件夹（只读识别） ─────────────────────
#
# empty_dots() 只认主目录下**以 . 开头**的目录（工具的隐藏状态目录）。
# 普通文件夹不在它的视野里 —— 用户报过：「Documents\kimi\workspace 这个目录
# 没有扫描到？这种应该是可以删除」。确实扫不到，因为 kimi 不是点目录。
# 这里专门补这一类：递归下去**一个文件都没有**的文件夹。

USER_EMPTY_ROOTS = ("Documents", "Desktop", "Downloads")

# 名字命中这些的一律不作为候选：系统目录（Documents / Desktop / Downloads 本身）
# 和版本库元数据（删了会让 git 认为工作区被改过）。
USER_EMPTY_SKIP = {
    "documents", "desktop", "downloads", "$recycle.bin",
    "system volume information", ".git", ".hg", ".svn",
}


def empty_user_dirs(budget=6.0, roots=None, max_depth=4, max_nodes=20000):
    """找出「文档 / 桌面 / 下载」里彻底空的文件夹。只读，不删任何东西。

    判定
        递归下去一个文件都没有才算空（空壳套空壳也算，父目录命中后子目录不再单列）。
        任何文件、junction、符号链接、没权限读进去的目录 —— 一律当作「有内容」，
        宁可漏报也不误判。

    不会碰的东西
        · 三个根本身（整个「文档」都空着也不能建议删掉「文档」）
        · 名字像系统目录的（leftover.SYSTEM_OWNED）
        · 点目录（归 empty_dots 管，避免两处重复列同一项）

    返回 {"items": [{path, rel, root, created}], "counts": {...},
          "truncated": bool, "elapsed": float}
    """
    started = time.time()
    deadline = started + max(1.0, float(budget))
    truncated = False
    items = []

    try:
        from .leftover import SYSTEM_OWNED
    except Exception:                       # 万一循环导入就退化成只拦 USER_EMPTY_SKIP
        SYSTEM_OWNED = set()

    base_roots = []
    for name in (roots or USER_EMPTY_ROOTS):
        full = name if os.path.isabs(name) else os.path.join(HOME, name)
        try:
            st = os.stat(full, follow_symlinks=False)
            if not os.path.isdir(full) or _is_reparse(st):
                continue
        except OSError:
            continue
        base_roots.append(os.path.normpath(full))

    nodes = 0
    for root in base_roots:
        # 广度优先：浅层的空文件夹先出结果，不会被某个几十万文件的大目录拖死在后面
        from collections import deque
        queue = deque([root])
        kids_of, has_file, order = {}, {}, []
        while queue:
            if time.time() > deadline or nodes >= max_nodes:
                truncated = True
                break
            cur = queue.popleft()
            order.append(cur)
            nodes += 1
            kids, dirty = [], False
            deep = cur.count(os.sep) - root.count(os.sep) + 1
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        try:
                            if not e.is_dir(follow_symlinks=False):
                                dirty = True          # 有文件 → 这层不是空的
                                continue
                            if _is_reparse(e.stat(follow_symlinks=False)):
                                dirty = True          # 链接当有内容，保守
                                continue
                            if deep >= max_depth:
                                dirty = True          # 不再往下，保守当有内容
                                continue
                            kids.append(e.path)
                        except OSError:
                            dirty = True
            except OSError:
                dirty = True                          # 读不进去 → 当有内容
            kids_of[cur], has_file[cur] = kids, dirty
            queue.extend(kids)

        empty = {}
        for cur in reversed(order):
            if cur not in kids_of:                    # 预算到了没扫到 → 不当空
                empty[cur] = False
                continue
            empty[cur] = (not has_file[cur]
                          and all(empty.get(k, False) for k in kids_of[cur]))

        for cur in order:
            if cur == root or not empty.get(cur):
                continue
            name = os.path.basename(cur)
            if name.lower() in USER_EMPTY_SKIP or name.lower() in SYSTEM_OWNED:
                continue
            if name.startswith("."):                  # 点目录归 empty_dots
                continue
            items.append({
                "path": cur,
                "rel": os.path.relpath(cur, HOME),
                "root": os.path.basename(root),
                "created": _stamp(cur),
            })

    items.sort(key=lambda x: x["rel"].lower())
    # 父目录已经是空的，子目录就别再单列了（删了父的，子自然没了）。
    # 不剪的话「Documents\kimi」和「Documents\kimi\workspace」会同时出现在清单里。
    kept, seen = [], set()
    for it in sorted(items, key=lambda x: x["path"].count(os.sep)):
        low = os.path.normcase(it["path"])
        if any(low.startswith(s + os.sep) for s in seen):
            continue
        seen.add(low)
        kept.append(it)
    items = sorted(kept, key=lambda x: x["rel"].lower())
    counts = {}
    for it in items:
        counts[it["root"]] = counts.get(it["root"], 0) + 1
    return {"items": items, "counts": counts, "truncated": truncated,
            "elapsed": round(time.time() - started, 1)}
