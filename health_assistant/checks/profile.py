"""
health_assistant.checks.profile — 用户目录梳理类巡检项

包含: profile.home / profile.dotfiles / profile.appdata / profile.secrets

四个检查共用一次 profile.scan()（ctx.cached），避免重复扫盘。
"""

from __future__ import annotations

from .. import profile
from ..core import Result, Severity, check, cli_cmd, short_path

__all__ = ["profile_home", "profile_dotfiles", "profile_appdata",
           "profile_secrets", "profile_empty_dots"]

CAT_LABEL = {
    "cache": "缓存", "model": "模型", "tool": "工具", "secret": "凭据",
    "other": "未识别", "data": "数据",
}
RISK_LABEL = {
    "safe": "可清", "repeat": "删了要重下", "review": "人工确认",
    "keep": "别动", "secret": "明文凭据",
}
EMPTY_KIND_LABEL = {"top": "顶层空壳", "cache": "缓存目录", "state": "工具状态"}


def _scan(ctx):
    """一次扫描，四个检查共用。"""
    pcfg = ctx.config.get("profile", {}) or {}
    return ctx.cached("profile.scan", lambda: profile.scan(
        budget=float(pcfg.get("budget", 20)),
        top=int(pcfg.get("top", 15)),
        min_mb=float(pcfg.get("min_mb", 200)),
        deep=bool(pcfg.get("deep", False)),
        dir_seconds=float(pcfg.get("dir_seconds", 5)),
    ))


def _size(n, truncated=False):
    return ("≥" if truncated else "") + profile.format_size(n)


def _cleanable(ctx, data):
    """全页统一的「可回收缓存」口径 —— 与 clean 命令实际会清的量一致。

    原来总览页按 min_mb=50 算、AppData 页按「safe+repeat 全部」算，
    同一台机器上能同时出现 9.5GB / 13.0GB / 16.1GB 三个数，用户只会觉得不可信。
    现在三处都走这一份：门槛取 cleanup.min_mb（clean 用的就是它），
    有目录因超时只统计了部分时，总量前面加「≥」，不再假装精确。
    """
    cmin = float((ctx.config.get("cleanup") or {}).get("min_mb", 10))
    cands = ctx.cached("profile.cleanable",
                       lambda: profile.cache_candidates(data, min_mb=cmin))
    total = sum(c["size"] for c in cands)
    truncated = any(c.get("truncated") for c in cands)
    return cands, total, truncated


@check("profile.home", "用户目录总览", group="profile", order=10,
       desc="用户主目录各文件夹体积 + 大文件清单")
def profile_home(ctx):
    res = Result()
    data = _scan(ctx)
    s = data["summary"]
    pcfg = ctx.config.get("profile", {}) or {}
    top = int(pcfg.get("top", 15))

    res.kv([
        ("用户目录", data["home"]),
        ("扫描耗时", f"{data['elapsed']}s（并行，单目录上限 "
                     f"{(ctx.config.get('profile', {}) or {}).get('dir_seconds', 5)}s）"),
        ("顶层文件夹", f"{s['home_dirs']} 个，合计 {profile.format_size(s['home_size'])}"),
        ("点目录/点文件", f"{s['dot_count']} 项（其中文件 {s['dot_file_count']} 个），"
                          f"合计 {profile.format_size(s['dot_size'])}"),
        ("AppData", f"{s['appdata_count']} 项，合计 {profile.format_size(s['appdata_size'])}"),
        ("大文件", f"{s['big_files']} 个 ≥{pcfg.get('min_mb', 200)}MB，"
                   f"合计 {profile.format_size(s['big_files_size'])}"),
    ])

    rows = []
    for it in sorted(data["home_dirs"], key=lambda x: -x["size"])[:top]:
        rows.append([it["name"][:22], _size(it["size"], it["truncated"]),
                     f"{it['files']:,}", f"{it['idle_days']}天", it["last_active"]])
    res.text("用户目录各文件夹（按体积）")
    res.table(["文件夹", "体积", "文件数", "最近写入", "最后活动"], rows,
              ["l", "r", "r", "r", "l"])

    if data["big_files"]:
        res.text(f"最大的 {len(data['big_files'])} 个文件（≥{pcfg.get('min_mb', 200)}MB）")
        res.table(["体积", "修改日期", "文件"],
                  [[profile.format_size(b["size"]), b["mtime"], short_path(b["path"], 62)]
                   for b in data["big_files"]],
                  ["r", "l", "l"])

    dl = next((i for i in data["home_dirs"] if i["name"].lower() == "downloads"), None)
    if dl:
        res.metrics["downloads_gb"] = round(dl["size"] / 1024 ** 3, 2)
    res.metrics.update({
        "home_total_gb": round(s["home_size"] / 1024 ** 3, 1),
        "dot_total_gb": round(s["dot_size"] / 1024 ** 3, 1),
        "big_files": s["big_files"],
        "big_files_gb": round(s["big_files_size"] / 1024 ** 3, 1),
    })

    if data["big_files"]:
        pkgs = [b for b in data["big_files"]
                if b["path"].lower().endswith((".zip", ".exe", ".msi", ".7z", ".rar", ".iso",
                                               ".tar", ".gz", ".vsix"))]
        if pkgs:
            pk = sum(b["size"] for b in pkgs)
            res.add(Severity.INFO,
                    f"{len(pkgs)} 个安装包/压缩包占 {profile.format_size(pk)}，"
                    f"装完就没用了，可手动删除",
                    impact="", fix="", kind="notice")
        res.add(Severity.INFO,
                f"{s['big_files']} 个大文件占 {profile.format_size(s['big_files_size'])}")

    # 全局空间总账放在总览页：缓存类可一条命令回收，数字与 clean 实际清理量同口径
    cands, cache_total, cache_trunc = _cleanable(ctx, data)
    if cache_total:
        def _tag(c):
            # 同名目录（Local\uv / Roaming\uv）靠上级目录区分
            bits = [x for x in c["path"].replace("/", "\\").split("\\") if x]
            tail = "/".join(bits[-2:]) if len(bits) >= 2 else bits[-1]
            return f"{tail}({profile.format_size(c['size'])})"
        part = "、".join(_tag(c) for c in cands[:4])
        size_txt = ("≥" if cache_trunc else "") + profile.format_size(cache_total)
        sev = Severity.WARN if cache_total >= 5 * 1024 ** 3 else Severity.INFO
        res.add(sev,
                f"用户目录有 {size_txt} 可回收缓存"
                f"（{len(cands)} 个目录：{part}{'…' if len(cands) > 4 else ''}）",
                impact="都是软件的下载缓存和临时文件，删掉下次用到会自动重建，不影响设置和登录。"
                       "第一条只列清单不删，确认后执行第二条（移到回收站，可还原）",
                fix=f"{cli_cmd('clean', '--kind', 'profile')}\n"
                    f"{cli_cmd('clean', '--kind', 'profile', '--yes')}",
                gain=f"释放 {size_txt}",
                save_bytes=cache_total)
        res.metrics["cache_cleanable_gb"] = round(cache_total / 1024 ** 3, 2)

    if dl and dl["size"] >= 5 * 1024 ** 3:
        res.add(Severity.INFO, f"下载目录 {profile.format_size(dl['size'])}，建议定期清理")
    if s["home_size"]:
        res.add(Severity.OK, f"用户目录合计 {profile.format_size(s['home_size'])}")

    if data["errors"]:
        for e in data["errors"][:3]:
            res.add(Severity.WARN, e)
    return res


@check("profile.dotfiles", "点目录梳理", group="profile", order=20,
       desc="用户目录下的 .xxx 目录/文件：体积、用途、能否清理")
def profile_dotfiles(ctx):
    res = Result()
    data = _scan(ctx)
    pcfg = ctx.config.get("profile", {}) or {}
    top = int(pcfg.get("top", 15))
    dots = sorted(data["dot"], key=lambda x: -x["size"])

    # 按类别汇总，先给结论再看明细
    agg = {}
    for it in dots:
        a = agg.setdefault(it["category"], {"n": 0, "size": 0, "files": 0})
        a["n"] += 1
        a["size"] += it["size"]
        a["files"] += it["files"]
    res.kv([("点目录总数", f"{len(dots)} 项，合计 {profile.format_size(sum(i['size'] for i in dots))}")])
    agg_rows = [[CAT_LABEL.get(k, k), f"{v['n']} 个", profile.format_size(v["size"]),
                 f"{v['files']:,}"] for k, v in sorted(agg.items(), key=lambda kv: -kv[1]["size"])]
    res.table(["类别", "个数", "体积", "文件数"], agg_rows, ["l", "r", "r", "r"])

    rows = []
    for it in dots[:top]:
        rows.append([it["name"][:20], _size(it["size"], it["truncated"]),
                     f"{it['files']:,}", f"{it['idle_days']}天",
                     RISK_LABEL.get(it["risk"], it["risk"]), it["desc"][:40]])
    res.text(f"体积最大的 {min(top, len(dots))} 个")
    res.table(["名称", "体积", "文件数", "最近写入", "风险", "用途"], rows,
              ["l", "r", "r", "r", "l", "l"])

    tiny = [it for it in dots if it["size"] < 1024]
    if tiny and len(dots) > top:
        res.text("其余 " + str(len(dots) - top) + " 项（多为空壳配置）: "
                 + ", ".join(i["name"] for i in dots[top:top + 24])
                 + (" …" if len(dots) > top + 24 else ""))

    cache_size = sum(i["size"] for i in dots if i["category"] == "cache")
    stale = [i for i in dots if i["idle_days"] >= 90 and i["category"] in ("tool", "cache")
             and i["size"] >= 100 * 1048576]

    res.metrics.update({
        "dot_count": len(dots),
        "dot_total_gb": round(sum(i["size"] for i in dots) / 1024 ** 3, 1),
        "dot_cache_gb": round(cache_size / 1024 ** 3, 1),
        "dot_stale_90d": len(stale),
    })

    if cache_size >= 500 * 1048576:
        res.add(Severity.INFO,
                f"点目录里的缓存共 {profile.format_size(cache_size)}"
                f"（已并入总览页的「可回收缓存」总账，一条命令清）",
                kind="info")
    if stale:
        names = ", ".join(f"{i['name']}({i['idle_days']}天)" for i in stale[:6])
        res.add(Severity.WARN, f"{len(stale)} 个点目录 90 天以上没写入但仍占空间: {names}",
                impact="长期没动过的工具目录，多数是卸载后留下的配置与缓存。"
                       "第一条先列清单，确认后执行第二条（移到回收站，可还原）",
                fix=f"{cli_cmd('clean', '--kind', 'profile')}\n"
                    f"{cli_cmd('clean', '--kind', 'profile', '--yes')}",
                gain="释放闲置占用")
    res.add(Severity.OK,
            f"{len(dots)} 个点目录合计 {profile.format_size(sum(i['size'] for i in dots))}")
    return res


@check("profile.appdata", "AppData 梳理", group="profile", order=30,
       desc="Roaming / Local / LocalLow 逐目录体积与缓存占比")
def profile_appdata(ctx):
    res = Result()
    data = _scan(ctx)
    pcfg = ctx.config.get("profile", {}) or {}
    top = int(pcfg.get("top", 15))

    for label in ("Roaming", "Local", "LocalLow"):
        items = sorted(data["appdata"].get(label) or [], key=lambda x: -x["size"])
        if not items:
            res.kv([(label, "无数据或读取失败")])
            continue
        total = sum(i["size"] for i in items)
        cache = sum(i["size"] for i in items if i["category"] == "cache")
        truncated = sum(1 for i in items if i["truncated"])
        head = (f"{len(items)} 项 / {profile.format_size(total)}"
                + (f"，其中缓存类 {profile.format_size(cache)}" if cache else "")
                + (f"，{truncated} 项因体积过大只统计了部分（标 ≥）" if truncated else ""))
        res.kv([(f"AppData\\{label}", head)])

        rows = []
        for it in items[:top]:
            rows.append([it["name"][:24], _size(it["size"], it["truncated"]),
                         f"{it['files']:,}", f"{it['idle_days']}天",
                         RISK_LABEL.get(it["risk"], it["risk"]), it["desc"][:34]])
        res.table(["目录", "体积", "文件数", "最近写入", "风险", "说明"], rows,
                  ["l", "r", "r", "r", "l", "l"])
        res.metrics[f"{label.lower()}_gb"] = round(total / 1024 ** 3, 1)

    s = data["summary"]
    res.metrics["appdata_total_gb"] = round(s["appdata_size"] / 1024 ** 3, 1)
    res.metrics["appdata_cache_gb"] = round(s["cache_size"] / 1024 ** 3, 1)

    # 用户目录缓存的可回收量统一由总览页出总账，这里只标注来源，避免同一台机器报出两个数
    cands, clean_total, clean_trunc = _cleanable(ctx, data)
    cache_items = [i for items in data["appdata"].values() for i in items
                   if i["category"] == "cache" and i["risk"] in ("safe", "repeat")]
    cache_items.sort(key=lambda x: -x["size"])
    if clean_total:
        size_txt = ("≥" if clean_trunc else "") + profile.format_size(clean_total)
        res.add(Severity.INFO,
                f"已并入总览页总账：可回收缓存 {len(cands)} 项 {size_txt}"
                f"（含点目录与 AppData，口径与 clean 命令一致）",
                kind="info")
    elif cache_items:
        res.add(Severity.INFO,
                f"{len(cache_items)} 个缓存目录都小于清理门槛，不值得动", kind="info")
    else:
        res.add(Severity.OK, "未发现明显可清理的缓存目录")
    return res


@check("profile.empty_dots", "空点目录", group="profile", order=50,
       desc="点目录里连一个文件都没有的空壳（可走回收站清理）")
def profile_empty_dots(ctx):
    res = Result()
    pcfg = ctx.config.get("profile", {}) or {}
    data = ctx.cached("profile.empty_dots", lambda: profile.empty_dots(
        budget=float(pcfg.get("empty_budget", 6)),
    ))
    if data.get("error"):
        return res.fail(f"扫描失败: {data['error']}")

    c = data["counts"]
    total = c["top"] + c["cache"] + c["state"]
    res.kv([
        ("空的点目录", f"{total} 个（{data['elapsed']}s"
                       + ("，超出预算已截断" if data["truncated"] else "") + "）"),
        ("顶层空壳", f"{c['top']} 个 —— 整个目录树里没有任何文件"),
        ("缓存/临时类", f"{c['cache']} 个 —— 路径含 cache / tmp / logs / downloads"),
        ("工具状态类", f"{c['state']} 个 —— 空着但程序可能预期它存在，谨慎"),
    ])

    rows = []
    for t in data["top"]:
        rows.append([t["rel"], EMPTY_KIND_LABEL["top"], f"{t['dirs']} 层", t["created"]])
    for n in data["nested"]:
        if n["kind"] == "cache":
            rows.append([n["rel"], EMPTY_KIND_LABEL["cache"], "-", n["created"]])
    for n in data["nested"]:
        if n["kind"] == "state":
            rows.append([n["rel"], EMPTY_KIND_LABEL["state"], "-", n["created"]])

    if rows:
        head = 24
        res.text(f"明细（前 {min(head, len(rows))} 条，共 {len(rows)} 条）")
        res.table(["相对路径", "类型", "层级", "创建日期"],
                  [[r[0][:64], r[1], r[2], r[3]] for r in rows[:head]],
                  ["l", "l", "l", "l"])
        if len(rows) > head:
            res.text(f"其余 {len(rows) - head} 条："
                     f"{cli_cmd('run', 'profile.empty_dots', '-f', 'json')} 可导出全量")

    targets = profile.empty_dot_targets(data)
    res.metrics.update({"empty_dots": total, "empty_top": c["top"],
                        "empty_cache": c["cache"], "empty_state": c["state"],
                        "empty_cleanable": len(targets)})

    if not total:
        res.add(Severity.OK, "没有发现空的点目录")
        return res

    if targets:
        sev = Severity.WARN if len(targets) >= 10 else Severity.INFO
        res.add(sev,
                f"{len(targets)} 个空目录可直接清掉（顶层空壳 + 缓存类）",
                impact="不占空间，只是让点目录干净一点，便于看清哪些是真在用的工具",
                fix=cli_cmd("clean", "--kind", "emptydot", "--yes"),
                gain=f"减少 {len(targets)} 个空目录")
        res.text(f"只想看看有哪些：{cli_cmd('clean', '--kind', 'emptydot')}\n"
                 f"连工具状态空目录一起清：在上面基础上加 --include-state")
    if c["state"]:
        res.add(Severity.INFO,
                f"{c['state']} 个工具状态目录为空，程序下次启动通常会重建，"
                f"没有洁癖可以不管")
    return res


@check("profile.secrets", "点目录里的明文凭据", group="profile", order=40,
       desc=".git-credentials / .npmrc / auth.json / JWT 等明文凭据排查（只读）")
def profile_secrets(ctx):
    res = Result()
    reveal = bool(ctx.config.get("reveal"))
    try:
        hits = profile.secret_files(reveal=reveal)
    except Exception as exc:
        return res.fail(f"凭据排查失败: {exc}")

    if not hits:
        res.kv([("明文凭据", "未发现（.git-credentials / .npmrc / .netrc / auth.json 等均未命中）")])
        res.add(Severity.OK, "用户目录未发现明文保存的凭据文件")
        res.metrics["profile_secrets"] = 0
        return res

    rows = []
    for h in hits:
        rows.append([profile.format_size(h["bytes"]), h["label"][:40],
                     f"{h['count']} 处", h["mtime"], short_path(h["path"], 52)]
                    + ([h["sample"]] if reveal else []))
    headers = ["大小", "类型", "命中", "修改日期", "文件"] + (["样例值"] if reveal else [])
    res.table(headers, rows, ["r", "l", "r", "l", "l"] + (["l"] if reveal else []))

    hard = [h for h in hits if "无口令" in h["label"] or "明文" in h["label"]]
    res.metrics["profile_secrets"] = len(hits)
    res.metrics["profile_secrets_plain"] = len(hard)

    # 逐个文件给出处置方式：能改配置的给命令，改不了的给明确动作。
    # 命令行里绝不拼 "# 说明" —— 用户整行粘进 cmd 时会被当成参数，直接报错。
    actions, notes = [], []
    for h in hits:
        p = h["path"]
        low = p.lower()
        base = p.split("\\")[-1]
        if base == ".git-credentials":
            actions.append("git config --global credential.helper manager")
            notes.append(f"{base} → 托管给 Windows 凭据管理器（DPAPI 加密），"
                         f"改完就可以把这个文件删掉")
        elif base in (".npmrc", ".netrc", ".pypirc"):
            notes.append(f"{base} → 把 token 挪到环境变量，再清掉文件里的明文段")
        elif base in ("auth.json", "credentials.json") or "token" in base:
            notes.append(f"{h['label']} → 改为环境变量注入，或收进凭据管理器")
        elif low.endswith((".pem", ".key")) or "id_rsa" in low or "id_ed25519" in low:
            actions.append(f'ssh-keygen -p -f "{p}"')
            notes.append(f"{base} → 上面那条 ssh-keygen 给它补一个口令")

    fix_lines = ["control /name Microsoft.CredentialManager"] + actions[:3]
    res.add(Severity.WARN,
            f"{len(hits)} 个文件存着明文凭据（token / 密钥 / 口令）",
            impact="这些文件被任何程序、备份、云同步读到，就等于账号直接交出去",
            fix="\n".join(fix_lines),
            gain="降低账号泄露风险")
    res.text("处置说明（命令在上面，说明在这里）：\n  "
             + "\n  ".join(notes or ["把明文 token 改存到环境变量或凭据管理器"]))
    if not reveal:
        res.text("  本轮已遮罩，未显示具体值（去掉 --mask 查看）")
    return res
