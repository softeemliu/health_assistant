"""
health_assistant.cli — 命令行入口

  health_assistant [分组或检查ID ...] [选项]
  health_assistant list
  health_assistant clean [--yes]
  health_assistant del-account  <TARGET|站点URL> [...]
  health_assistant set-account  <TARGET> --user U --password P
  health_assistant import-passwords <浏览器导出的.csv>
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
import time

from . import __version__, checks, credentials           # noqa: F401  导入 checks 以注册
from . import leftover, metrics, planclean, render, slim
from .core import (Context, Severity, cli_cmd, dwidth, get_checks, hostname,
                   is_admin, load_config, now_str, pad, short_path)
from .runner import DEFAULT_WORKERS, load_plugins, run_checks

TOOL = f"health_assistant {__version__}"
FORMATS = ("text", "json", "md")
COMMANDS = ("run", "list", "del-account", "set-account", "clean", "import-passwords",
            "kill", "port", "proc", "mem", "lock", "startup", "du", "smart")


# ───────────────────────────── 参数 ─────────────────────────────

def _common(p):
    # argparse 会对 help 做 % 格式化，这里必须转义成 %%
    p.add_argument("--config", metavar="FILE", help="配置文件（默认 %%APPDATA%%\\health_assistant\\config.json）")
    p.add_argument("--plugin-dir", action="append", default=[], metavar="DIR",
                   help="额外插件目录，可重复")
    p.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    p.add_argument("--reveal", action="store_true",
                   help="显示密码明文（默认已开启，仅为兼容旧命令保留）")
    p.add_argument("--mask", action="store_true",
                   help="遮罩密码（默认明文显示，需要打码/外发报告时用）")
    p.add_argument("-v", "--verbose", action="store_true", help="输出插件加载等调试信息")
    return p


def build_parser():
    p = argparse.ArgumentParser(
        prog="health_assistant",
        description="Windows 本机巡检应用框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例（下面的 health_assistant 就是项目根目录的 health_assistant.cmd；\n"
               "      在别的目录要带绝对路径，见末尾「入口」）:\n"
               "  health_assistant                              # 全量巡检\n"
               "  health_assistant profile                      # 只梳理用户目录\n"
               "  health_assistant cpu,memory                   # CPU 与内存（含进程启动参数）\n"
               "  health_assistant --format md --out r.md       # 导出 Markdown\n"
               "  health_assistant port --all                   # 端口 + 进程 + 启动参数\n"
               "  health_assistant proc mysqld                  # 单进程详情\n"
               "  health_assistant kill --port 8080             # 终止占用端口的进程\n"
               "  health_assistant clean --kind profile         # 只看用户目录缓存（不删）\n"
               "  health_assistant clean --yes                  # 移到回收站\n"
               "  health_assistant import-passwords pw.csv      # 浏览器导出的密码\n"
               "\n入口:\n"
               "  双击 启动巡检.pyw                       # 图形界面（不弹黑窗）\n"
               f"  {cli_cmd()}   # 命令行（任意目录可用，绝对路径）\n"
               "\n注意: python -m health_assistant 只有站在项目根目录时才有效"
               "（包没装进 site-packages）。\n",
    )
    p.add_argument("-V", "--version", action="version", version=TOOL)
    sub = p.add_subparsers(dest="cmd")

    pr = _common(sub.add_parser("run", help="执行巡检（默认）"))
    pr.add_argument("selector", nargs="*", help="分组名或检查ID，留空=全部")
    pr.add_argument("-f", "--format", choices=FORMATS, default="text", help="输出格式")
    pr.add_argument("-o", "--out", metavar="FILE", help="写入文件")
    pr.add_argument("--timeout", type=int, help="单项超时秒数（覆盖配置）")
    pr.add_argument("--workers", type=int,
                    help="并行执行几个检查项（默认取配置 workers，内置 6）")
    pr.add_argument("--full", action="store_true",
                    help="文本模式连正常项也展开（默认只列要处理的事）")
    pr.add_argument("--fail-on", choices=("none", "warn", "error"), default="none",
                    help="达到该等级时以非 0 退出码结束（供 CI/定时任务判断）")
    pr.add_argument("--progress", action="store_true", help="边跑边在 stderr 显示进度")
    pr.add_argument("--metrics", action="store_true", help="文本输出附带 metrics")

    pl = _common(sub.add_parser("list", help="列出所有检查项"))
    pl.add_argument("--format", choices=("text", "json"), default="text")

    pd = _common(sub.add_parser("del-account", help="删除账号凭据"))
    pd.add_argument("target", help="凭据 TargetName（--browser 时为站点 URL）")
    pd.add_argument("--user", help="浏览器条目：限定用户名")
    pd.add_argument("--browser", action="store_true", help="操作浏览器已保存登录（要求浏览器退出）")
    pd.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    ps = _common(sub.add_parser("set-account", help="新增/更新账号凭据"))
    ps.add_argument("target", help="凭据 TargetName")
    ps.add_argument("--user", required=True, help="用户名")
    ps.add_argument("--password", required=True, help="密码")
    ps.add_argument("--browser", action="store_true", help="（不支持）浏览器密码写入")

    pc = _common(sub.add_parser("clean", help="清理系统盘残留 / 用户目录缓存（移到回收站）"))
    pc.add_argument("--min-mb", type=float, help="只处理不小于该体积的目录")
    pc.add_argument("--older", type=int, help="只处理闲置不少于 N 天的目录")
    pc.add_argument("--active-days", type=int, help="最近 N 天有写入视为在用（默认 45）")
    pc.add_argument("--kind", choices=("leftover", "cache", "profile", "emptydot",
                                       "slim", "zombie", "userjunk", "all"),
                    default="leftover",
                    help="残留 / 工具链缓存 / 用户目录缓存 / 空点目录 / "
                         "系统盘瘦身(slim) / 僵尸文件(zombie) / 无用用户文件(userjunk) / 全部")
    pc.add_argument("--cache-repeat", action="store_true",
                    help="连「删了要重新下载」的缓存一起清（默认只清纯缓存）")
    pc.add_argument("--include-state", action="store_true",
                    help="emptydot 时连「工具状态」空目录一起清（默认只清顶层空壳 + 缓存类）")
    pc.add_argument("--system-names", action="store_true",
                    help="允许清理名字像系统目录的目标（temp/tmp/packages 等，默认拦截）")
    pc.add_argument("--root", action="append", metavar="DIR", help="限定扫描根目录，可重复")
    pc.add_argument("--path", action="append", metavar="DIR", help="只处理指定目录（可重复）")
    pc.add_argument("--batch", type=int, help="一次最多处理几个条目（默认 10；瘦身建议 200）")
    pc.add_argument("--all", action="store_true", help="列出全部候选（默认只列前 30）")
    pc.add_argument("--dry-run", action="store_true", help="只看不删（默认行为）")
    pc.add_argument("-y", "--yes", action="store_true", help="跳过确认，直接移到回收站")

    pi = _common(sub.add_parser("import-passwords", help="读取浏览器导出的密码 CSV 并展示"))
    pi.add_argument("csv_file", nargs="?", help="Chrome/Edge 导出的密码 CSV 路径")
    pi.add_argument("--match", action="store_true", help="与浏览器已保存登录做比对")
    pi.add_argument("--save", action="store_true",
                    help="把 CSV 明文并入本地缓存，后续报告自动补齐 v20 条目")
    pi.add_argument("--clear", action="store_true", help="清空已并入的 CSV 缓存")
    pi.add_argument("--show-cache", action="store_true", help="只列出缓存里已有的条目")
    pi.add_argument("--auto", action="store_true",
                    help="自动在下载目录里找最新的密码导出 CSV 并并入")
    pi.add_argument("--wait", type=int, default=0, metavar="秒",
                    help="配合 --auto：等待导出文件出现的最长秒数")

    # ---- 进程 / 端口（既能看，也能动手） ----
    pk = _common(sub.add_parser("kill", help="终止进程（按 PID / 进程名 / 端口定位）"))
    pk.add_argument("target", nargs="*", help="PID 或进程名（可多个）")
    pk.add_argument("--pid", action="append", type=int, help="按 PID 指定，可重复")
    pk.add_argument("--port", action="append", type=int, help="终止监听该端口的进程，可重复")
    pk.add_argument("--tree", action="store_true", help="连同子进程一起终止")
    pk.add_argument("--force", action="store_true",
                    help="允许终止系统关键进程名（svchost/lsass 等，危险）")
    pk.add_argument("--list", action="store_true", help="只列出匹配到的进程，不终止")
    pk.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    pp = _common(sub.add_parser("port", help="监听端口速查（含进程名与启动参数）"))
    pp.add_argument("--port", action="append", type=int, help="只看指定端口，可重复")
    pp.add_argument("--all", action="store_true", help="不截断，列全部")
    pp.add_argument("--tree", action="store_true", help="配合 --kill，连同子进程终止")
    pp.add_argument("--kill", action="store_true", help="终止占用这些端口的进程")
    pp.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    ppc = _common(sub.add_parser("proc", help="进程详情（路径 / 完整参数 / 监听端口 / 子进程）"))
    ppc.add_argument("target", nargs="*", help="PID 或进程名")

    pm = _common(sub.add_parser("mem", help="内存总览 / 释放闲置进程的内存 / 清空待机缓存"))
    pm.add_argument("--top", type=int, default=15, help="列出内存占用前 N 个进程（默认 15）")
    pm.add_argument("--min-mb", type=float, default=300,
                    help="只释放工作集 ≥ 该体积的进程（默认 300MB）")
    pm.add_argument("--trim", action="store_true", help="对符合条件的进程执行释放（默认只看不动）")
    pm.add_argument("--only", action="append", type=int,
                    help="只处理指定 PID，可重复（配合 --trim）")
    pm.add_argument("--purge", action="store_true",
                    help="清空待机列表（需要管理员；会拖慢之后的读盘）")
    pm.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    plk = _common(sub.add_parser("lock", help="查谁占着文件/文件夹（可选：让它正常退出 / 强制结束）"))
    plk.add_argument("path", help="文件或文件夹路径")
    plk.add_argument("--close", action="store_true",
                     help="给占用进程的主窗口发关闭消息（等于替用户点 ×，最安全）")
    plk.add_argument("--kill", action="store_true", help="强制结束占用进程（会丢未保存数据）")
    plk.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    pst = _common(sub.add_parser("startup", help="开机自启项：查看 / 停用 / 恢复（可逆，不删注册表）"))
    pst.add_argument("--disable", action="append", metavar="名称",
                     help="停用指定的自启项（可重复；名称按列表里的「名称」列）")
    pst.add_argument("--enable", action="append", metavar="名称",
                     help="恢复指定的自启项（可重复）")
    pst.add_argument("--undo", action="store_true", help="撤销最近一次停用/恢复")
    pst.add_argument("-y", "--yes", action="store_true", help="跳过确认")

    pdu = _common(sub.add_parser("du", help="看一个目录下谁最占地方（只统计，不删）"))
    pdu.add_argument("path", nargs="?", default=None,
                     help="目录路径，默认列出盘符")
    pdu.add_argument("--top", type=int, default=25, help="列出前 N 项（默认 25）")
    pdu.add_argument("--min-mb", type=float, default=0,
                     help="只看不小于该体积的项（默认全看）")
    pdu.add_argument("--budget", type=float, default=25.0,
                     help="统计时间预算，秒（默认 25；没算完的标 ≥）")

    psm = _common(sub.add_parser("smart", help="硬盘健康：SMART 状态、磨损、温度、通电时间"))
    return p


def _normalize_args(argv):
    """没有子命令时默认走 run，便于 `health_assistant --format md` 这种用法。"""
    argv = list(argv)
    if argv and argv[0] in ("-h", "--help", "-V", "--version"):
        return argv
    if not argv or argv[0] not in COMMANDS:
        return ["run"] + argv
    return argv


# ───────────────────────────── run ─────────────────────────────

def _meta():
    return {
        "tool": TOOL,
        "host": hostname(),
        "os": f"{platform.system()} {platform.release()} (build {platform.version()})",
        "user": os.environ.get("USERNAME", "?"),
        "admin": is_admin(),
        "time": now_str(),
    }


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def cmd_run(args):
    cfg, cfg_src = load_config(args.config)
    if getattr(args, "mask", False):
        cfg["reveal"] = False
    elif getattr(args, "reveal", False):
        cfg["reveal"] = True
    if args.verbose and cfg_src:
        print(f"  配置来源: {cfg_src}", file=sys.stderr)

    # 插件目录: 内置 plugins/ + 配置 + 命令行
    plugin_dirs = list(cfg.get("plugin_dirs") or [])
    default_plugins = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins")
    if os.path.isdir(default_plugins):
        plugin_dirs.append(default_plugins)
    plugin_dirs += list(args.plugin_dir or [])

    errors = load_plugins(plugin_dirs, verbose=args.verbose)
    for path, err in errors:
        print(f"  [插件加载失败] {path}: {err}", file=sys.stderr)

    selector = ",".join(args.selector) if args.selector else None
    items_checks = get_checks(selector, include_disabled=cfg.get("disabled") or [])
    if not items_checks:
        print(f"没有匹配的检查项: {selector}", file=sys.stderr)
        print("可用分组: " + ", ".join(sorted({c.group for c in get_checks()})), file=sys.stderr)
        print(f"查看全部检查项: {cli_cmd('list')}", file=sys.stderr)
        return 1

    ctx = Context(cfg, verbose=args.verbose)
    timeout = args.timeout if args.timeout is not None else int(cfg.get("timeout", 60))

    # 进度回调
    state = {"i": 0}
    total = len(items_checks)

    def progress(chk, res):
        if not args.progress:
            return
        state["i"] += 1
        sys.stderr.write(f"\r  [{state['i']:>2}/{total}] {chk.id:<22} "
                         f"{res.status:<5} {res.elapsed_ms:>5}ms   ")
        sys.stderr.flush()

    items, summary = [], None
    workers = args.workers if getattr(args, "workers", None) else cfg.get("workers") or DEFAULT_WORKERS
    for chk, res in run_checks(items_checks, ctx, timeout=timeout,
                               progress=progress, workers=workers):
        if chk is None:
            summary = res                      # 末位哨兵 = Summary
        else:
            items.append((chk, res))
    if args.progress:
        sys.stderr.write("\r" + " " * 70 + "\r")
    # 并发完成顺序是乱的，报告里按原定检查顺序排回去
    order = {c.id: i for i, c in enumerate(items_checks)}
    items.sort(key=lambda cr: order.get(cr[0].id, 0))

    meta = _meta()
    fmt = args.format

    if fmt == "json":
        text = render.render_json(meta, items, summary)
    elif fmt == "md":
        text = render.render_markdown(meta, items, summary)
    else:
        text = render.render_text(meta, items, summary,
                                  color=(not args.no_color and sys.stdout.isatty()),
                                  show_metrics=args.metrics,
                                  full=getattr(args, "full", False))

    out = args.out
    if out:
        if cfg.get("reveal"):
            print("  [注意] 报告含密码明文，外发前请确认；需要打码加 --mask", file=sys.stderr)
        _write(out, text)
        print(f"已写入: {os.path.abspath(out)}")
    else:
        print(text)

    # 退出码
    if args.fail_on == "error" and summary.worst == Severity.ERROR:
        return 3
    if args.fail_on == "warn" and Severity.RANK[summary.worst] >= Severity.RANK[Severity.WARN]:
        return 2
    return 0


# ───────────────────────────── list ─────────────────────────────

def cmd_list(args):
    cfg, _src = load_config(args.config)
    allc = get_checks(None, include_disabled=cfg.get("disabled") or [])
    disabled = set(cfg.get("disabled") or [])

    if args.format == "json":
        import json
        print(json.dumps([
            {"id": c.id, "title": c.title, "group": c.group, "order": c.order,
             "admin": c.admin, "desc": c.desc, "tags": list(c.tags),
             "disabled": c.id in disabled}
            for c in allc], ensure_ascii=False, indent=2))
        return 0

    from .core import GROUP_TITLES, pad
    print(f"{TOOL}  已注册 {len(allc)} 个检查项\n")
    print("  " + pad("分组", 10) + " " + pad("检查ID", 22) + " "
          + pad("标题", 16) + " 说明")
    print("  " + "-" * 92)
    for c in allc:
        print("  " + pad(c.group, 10) + " " + pad(c.id, 22) + " "
              + pad(c.title, 16) + " "
              + ("[需管理员] " if c.admin else "") + c.desc
              + ("  (已禁用)" if c.id in disabled else ""))
    print("\n  分组说明: " + ", ".join(f"{k}={v}" for k, v in GROUP_TITLES.items()))
    print("  选择执行: health_assistant <分组名|检查ID> ...")
    return 0


# ───────────────────────────── 账号维护 ─────────────────────────────

def cmd_del_account(args):
    if args.browser:
        ok, msg = credentials.browser_delete(args.target, args.user, assume_yes=args.yes)
        print(("  [OK]   " if ok else "  [BAD]  ") + msg)
        return 0 if ok else 1
    try:
        allc = credentials.cred_enum()
    except Exception as exc:
        print(f"  [BAD]  枚举凭据失败: {exc}")
        return 1

    hit = [c for c in allc if c["target"].lower() == args.target.lower()]
    if not hit:
        fuzzy = [c for c in allc if args.target.lower() in c["target"].lower()]
        if not fuzzy:
            print(f"  [BAD]  未找到凭据: {args.target}")
            return 1
        if len(fuzzy) > 1:
            print(f"  [WARN] 未精确匹配，相近 {len(fuzzy)} 条:")
            for c in fuzzy:
                print(f"           {c['target']}   user={c['user']}")
            print("  [BAD]  请用完整 TargetName")
            return 1
        hit = fuzzy

    c = hit[0]
    print(f"  目标  : {c['target']}")
    print(f"  用户名: {c['user'] or '-'}")
    print(f"  类型  : {c['type_name']}")
    if not args.yes:
        if input("  确认删除该凭据? (y/N) ").strip().lower() not in ("y", "yes"):
            print("  [WARN] 已取消")
            return 0

    # 红线：先备份「删了什么」再删（密码本身无法还原，界面文案已说明）
    bak, err = credentials.cred_backup([c])
    if not bak:
        print(f"  [BAD]  备份失败，已取消删除: {err}")
        return 1
    print(f"  备份  : {bak}")

    ok, err = credentials.cred_delete(c["target"])
    print(("  [OK]   已删除: " if ok else "  [BAD]  删除失败: ")
          + (c["target"] if ok else f"{err}（可能需要管理员权限）"))
    return 0 if ok else 1


def cmd_set_account(args):
    if args.browser:
        print("  [BAD]  浏览器密码写入不支持：需要按浏览器密钥重新加密，属于凭据注入能力。")
        print("         请在浏览器 设置→密码 修改，或先 del-account --browser 删除后重新保存。")
        return 1

    exists = any(c["target"].lower() == args.target.lower() for c in credentials.cred_enum())
    ok, err = credentials.cred_write(args.target, args.user, args.password)
    if ok:
        print(f"  目标  : {args.target}")
        print(f"  用户名: {args.user}")
        print(f"  密码  : ********")
        print("  [OK]   " + ("已更新" if exists else "已新增"))
        return 0
    print(f"  [BAD]  写入失败: {err}（可能需要管理员权限）")
    return 1


# ───────────────────────────── clean ─────────────────────────────

def _human(n):
    return leftover.format_size(n)


def _write_clean_ledger(kind, ok_list, bad):
    """把本次清理的成败逐条落盘（终端输出会滚走，审计要能回查）。"""
    return planclean.write_ledger(kind, ok_list, bad)


def cmd_clean(args):
    """扫描并把残留 / 缓存目录移到回收站。默认只报告。"""
    cfg, _src = load_config(args.config)
    ccfg = cfg.get("cleanup", {}) or {}
    pcfg = cfg.get("profile", {}) or {}
    min_mb = args.min_mb if args.min_mb is not None else float(ccfg.get("min_mb", 10))
    active_days = args.active_days if args.active_days is not None else int(ccfg.get("active_days", 45))
    batch = args.batch if args.batch is not None else int(ccfg.get("batch", 10))
    # 瘦身候选动辄一两百条（临时目录 + 快捷方式 + 安装包），沿用「一次 10 个」
    # 会变成反复重跑十几次，这里给一个更适合的默认值；用户显式 --batch 时以他为准。
    if args.batch is None and args.kind in ("slim", "zombie", "userjunk"):
        batch = int(ccfg.get("slim_batch", 200))

    plan = planclean.collect(
        kind=args.kind, min_mb=min_mb, older=args.older or 0, active_days=active_days,
        roots=args.root, cache_repeat=args.cache_repeat,
        include_state=bool(getattr(args, "include_state", False)),
        paths=args.path, profile_budget=pcfg.get("budget", 20),
        empty_budget=pcfg.get("empty_budget", 6),
        slim_budget=ccfg.get("slim_budget", 25),
        slim_older=ccfg.get("slim_older", 60),
        on_log=lambda s: print("  " + s))

    cands = plan["cands"]
    data = {"scanned_dirs": plan["scanned"], "elapsed": plan["elapsed"],
            "errors": plan["errors"], "ghosts": plan["ghosts"]}
    profile_paths = plan["profile_paths"]
    empty_paths = plan["empty_paths"]
    pres = plan["pres"]

    for err in data["errors"]:
        print(f"  [WARN] {err}")

    if not cands:
        print("  未发现符合条件的目标（可以用 --min-mb 降低阈值，或 --older 放宽闲置天数）")
        return 0

    total = sum(c["size"] for c in cands)
    show = cands if args.all else cands[:30]
    slim_res = plan.get("slim") or {}
    if slim_res:
        unit = "项"
        scan_note = f"瘦身扫描 {slim_res['elapsed']}s"
        if slim_res.get("small_files"):
            scan_note += (f"；另有 {slim_res['small_files']} 个零散小文件"
                          f"（{_human(slim_res['small_bytes'])}）因体积过小未列出")
    else:
        unit = "个目录"
        scan_note = f"扫描 {data['scanned_dirs']} 个目录 / {data['elapsed']}s"
        if pres:
            scan_note += f"；用户目录 {pres['elapsed']}s"
    if total:
        total_txt = _human(total)
    elif empty_paths:
        total_txt = f"0B（{len(empty_paths)} 个空目录，不占空间）"
    else:
        total_txt = "0B"
    print(f"\n  候选 {len(cands)} {unit}，合计 {total_txt}  （{scan_note}）\n")
    print("  " + pad("#", 3) + pad("体积", 10, "r") + pad("闲置", 8, "r")
          + " " + pad("来源", 8) + "  路径 / 说明")
    print("  " + "-" * 96)
    for n, c in enumerate(show, 1):
        src = planclean.source_of(c, profile_paths)
        print("  " + pad(n, 3) + pad(_human(c["size"]), 10, "r")
              + pad(f"{c.get('idle_days', 0)}天", 8, "r")
              + " " + pad(src, 8) + f"  {c['path']}"
              + (f"\n      说明: {c['note']}" if c.get("note") else ""))
    if len(cands) > len(show):
        print(f"  …另有 {len(cands) - len(show)} 个未显示（--all 查看）")

    if data["ghosts"]:
        print(f"\n  另有 {len(data['ghosts'])} 条注册表幽灵项"
              "（本命令不改注册表；要清就在图形界面的「清理」页点「注册表残留」）")

    if args.dry_run or not args.yes:
        print("\n  以上仅为扫描结果，未做任何修改。")
        if args.dry_run:
            return 0
        if not sys.stdin.isatty():
            # 非交互环境（定时任务/管道）不猜用户意图，一律不删
            print("  非交互环境，未执行删除。确认后加 --yes 重跑。")
            return 0
        try:
            ans = input(f"  将这些目录移到回收站（{total_txt}）? 输入 yes 确认: ").strip()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans.lower() not in ("yes", "y"):
            print("  已取消")
            return 0

    targets = [c["path"] for c in cands[:batch]]
    print(f"\n  正在移到回收站（{len(targets)} 个，可撤销）…")
    # 瘦身候选（僵尸文件 / 无用用户文件）走 slim 自己的白名单与四道闸：
    # 它们包含文件（.lnk/.dmp/.msi），而 trash_paths 只接受目录。
    slim_targets = [c["path"] for c in cands[:batch] if c.get("origin") == "slim"]
    dir_targets = [c["path"] for c in cands[:batch] if c.get("origin") != "slim"]
    ok_list, bad = [], []
    if dir_targets:
        o, b = leftover.trash_paths(
            dir_targets, max_batch=batch, allow_exact=profile_paths,
            allow_system_names=bool(getattr(args, "system_names", False)))
        ok_list += o
        bad += b
    if slim_targets:
        o, b = slim.trash(slim_targets, max_batch=batch)
        ok_list += o
        bad += b
    freed = 0
    for p, note in ok_list:
        size = next((c["size"] for c in cands if c["path"] == p), 0)
        freed += size
        print(f"  [OK]   {p}\n         {note}")
    for p, why in bad:
        print(f"  [BAD]  {p}\n         原因: {why}")

    freed_txt = _human(freed) if freed else "0B（空目录）"
    print(f"\n  完成：{len(ok_list)} 个成功，约 {freed_txt}；{len(bad)} 个失败")
    ledger = _write_clean_ledger(args.kind, ok_list, bad)
    if ledger:
        print(f"  台账: {short_path(ledger, 70)}（逐条记录删了什么，便于事后核对）")
    if len(cands) > batch:
        print(f"  还有 {len(cands) - batch} 个未处理（受 --batch {batch} 限制，可再跑一次）")
    print("  提示：文件在回收站里，确认无误后再清空回收站。")
    return 0 if not bad else 1


# ───────────────────────────── import-passwords ─────────────────────────────

def cmd_import_passwords(args):
    """展示浏览器导出的密码 CSV；--save 并入缓存，后续报告自动补齐 v20 条目。"""
    if args.clear:
        gone = credentials.clear_imported()
        print("  已清空 CSV 缓存" if gone else "  缓存本来就是空的")
        if not args.csv_file:
            return 0

    if args.auto and not args.csv_file:
        started = time.time()
        found = None
        while True:
            found, age = credentials.find_export_csv()
            if found:
                break
            if time.time() - started >= max(0, args.wait):
                break
            if args.wait:
                print("  等待导出文件…（在 Chrome 里点『导出密码』并确认 Windows 登录）",
                      end="\r", flush=True)
                time.sleep(1.0)
        if not found:
            print("  没找到密码导出 CSV。检查位置:")
            for d in credentials.download_dirs():
                print(f"    · {d}")
            print("  先在 chrome://password-manager/settings 导出密码，再重跑；"
                  "或用 --wait 120 让它等文件出现。")
            return 2
        args.csv_file = found
        print(f"  自动定位到导出文件: {short_path(found, 70)}")
        args.save = True   # --auto 的语义就是并入

    if args.show_cache or (not args.csv_file):
        cache = credentials.load_imported()
        if not cache:
            print(f"  缓存为空（{short_path(credentials.IMPORT_CACHE, 60)}）")
            print(f"  用法: {cli_cmd('import-passwords')} CSV文件路径 --save")
            return 0 if args.show_cache else 2
        print(f"  缓存里 {len(cache)} 条（{short_path(credentials.IMPORT_CACHE, 60)}）\n")
        print("  " + pad("站点", 44) + pad("用户名", 22) + pad("密码", 30) + "导入时间")
        print("  " + "-" * 108)
        for v in sorted(cache.values(), key=lambda x: x.get("origin", "")):
            print("  " + pad((v.get("origin") or "")[:42], 44)
                  + pad((v.get("user") or "-")[:20], 22)
                  + pad(v.get("password") or "", 30) + str(v.get("at", "")))
        return 0

    try:
        rows = credentials.import_password_csv(args.csv_file)
    except FileNotFoundError:
        print(f"  [BAD]  文件不存在: {args.csv_file}")
        return 1
    except Exception as exc:
        print(f"  [BAD]  解析失败: {exc}")
        return 1

    if not rows:
        print("  [WARN] CSV 里没有数据行")
        return 0

    print(f"  读取到 {len(rows)} 条密码（来源: {os.path.basename(args.csv_file)}）\n")
    print("  " + pad("站点", 44) + pad("用户名", 22) + "密码")
    print("  " + "-" * 92)
    for r in rows:
        url = r["url"] if len(r["url"]) <= 42 else r["url"][:41] + "…"
        print("  " + pad(url, 44) + pad((r["user"] or "-")[:20], 22) + (r["password"] or ""))

    if args.save:
        total, n = credentials.save_imported(rows, source=args.csv_file)
        print(f"\n  已并入缓存 {n} 条（缓存共 {total} 条）: "
              f"{short_path(credentials.IMPORT_CACHE, 60)}")
        print("  之后 account.inventory 与报告里的 v20 条目会自动用这里的明文补齐；")
        print(f"  {cli_cmd('import-passwords', '--clear')} 可随时清空。")

    if args.match:
        try:
            stored = credentials.browser_logins()
        except Exception:
            stored = []
        have = {(s["origin"].lower(), (s["user"] or "").lower()) for s in stored}
        matched = sum(1 for r in rows if (r["url"].lower(), r["user"].lower()) in have)
        extra = len(rows) - matched
        print(f"\n  与浏览器已保存登录比对：匹配 {matched} 条，另有 {extra} 条只在 CSV 里")
        if extra:
            print("  （说明 CSV 里有浏览器当前未保存的条目，或导出于不同时间点）")

    if not args.save:
        print("\n  说明：明文仅打印到终端，未落盘。加 --save 才会并入本地缓存。")
    return 0


# ───────────────────────────── 进程 / 端口 ─────────────────────────────

def _match_procs(args, sample=0.3):
    """按 PID / 进程名 / 端口 解析出目标进程（已补全 exe 与启动参数）。"""
    want_pids = set(getattr(args, "pid", None) or [])
    ports = set(getattr(args, "port", None) or [])
    name_keys = set()
    for t in (getattr(args, "target", None) or []):
        t = str(t).strip()
        if not t:
            continue
        if t.isdigit():
            want_pids.add(int(t))
        else:
            low = t.lower()
            name_keys.add(low[:-4] if low.endswith(".exe") else low)

    snap = metrics.proc_snapshot(sample=sample)
    hits = {}
    for r in snap:
        base = r["name"].lower()
        stem = base[:-4] if base.endswith(".exe") else base
        if r["pid"] in want_pids or stem in name_keys or base in name_keys:
            hits[r["pid"]] = r

    if ports:
        for r in metrics.net_listeners():
            if r["port"] in ports and r["pid"] not in hits:
                mem = priv = 0
                try:
                    p = metrics.psutil.Process(r["pid"])
                    with p.oneshot():
                        mi = p.memory_info()
                        mem = mi.rss
                        priv = getattr(mi, "private", 0)
                except Exception:
                    pass
                hits[r["pid"]] = {
                    "pid": r["pid"], "ppid": r.get("ppid") or 0, "name": r["name"],
                    "cpu": 0.0, "mem": mem, "mem_priv": priv, "exe": r.get("exe") or "",
                    "cmdline": r.get("cmdline") or "", "user": r.get("user") or "",
                    "started": 0, "status": "", "detail": True,
                }
    return metrics.enrich_procs(sorted(hits.values(), key=lambda x: x["pid"]))


def _print_proc_table(rows, width=96):
    print("  " + pad("PID", 7, "r") + " " + pad("进程", 24) + " "
          + pad("CPU%", 6, "r") + " " + pad("内存", 10, "r") + "  启动参数 / 路径")
    print("  " + "-" * (width + 20))
    for r in rows:
        cmd = r.get("cmdline") or r.get("exe") or "-"
        if dwidth(cmd) > width:
            cmd = cmd[:width - 12] + " … " + cmd[-8:]
        print("  " + pad(r["pid"], 7, "r") + " " + pad(r["name"][:24], 24) + " "
              + pad(f"{r.get('cpu', 0):.1f}", 6, "r") + " "
              + pad(_human(r.get("mem") or 0), 10, "r") + "  " + cmd)


def cmd_kill(args):
    rows = _match_procs(args)
    if not rows:
        print("  未匹配到进程。请给出 PID、进程名，或用 --port <端口>。")
        print(f"  查看全量: {cli_cmd('port', '--all')}")
        return 1

    print(f"  匹配到 {len(rows)} 个进程：\n")
    _print_proc_table(rows)
    if getattr(args, "list", False):
        return 0

    me = os.getpid()
    plan, refused = [], []
    for r in rows:
        low = r["name"].lower()
        if r["pid"] <= 4:
            refused.append((r, "系统核心进程（System / 内核），不可终止"))
        elif r["pid"] == me:
            refused.append((r, "巡检工具自身"))
        elif low in metrics.KILL_BLOCK_NAMES and not args.force:
            refused.append((r, "系统关键进程（确需终止请加 --force）"))
        else:
            plan.append(r)

    for r, why in refused:
        print(f"  [SKIP] {r['name']}({r['pid']}): {why}")
    if not plan:
        print("\n  没有可终止的进程。")
        return 1

    if not args.yes:
        if not sys.stdin.isatty():
            print("\n  非交互环境，未执行终止。确认后加 --yes 重跑。")
            return 0
        tip = "（含子进程树）" if args.tree else ""
        ans = input(f"\n  终止以上 {len(plan)} 个进程{tip}? 输入 yes 确认: ").strip()
        if ans.lower() not in ("yes", "y"):
            print("  已取消")
            return 0

    all_ok = True
    for r in plan:
        ok, notes = metrics.kill_process(r["pid"], tree=args.tree, force=args.force)
        print(f"  [{'OK ' if ok else 'BAD'}] {r['name']}({r['pid']})")
        for n in notes:
            print("         " + n)
        all_ok = all_ok and ok
    return 0 if all_ok else 1


def cmd_port(args):
    lst = metrics.net_listeners()
    if not lst:
        print("  读取端口失败（需要管理员权限，或 psutil 缺失）")
        return 1

    ports = set(args.port or [])
    if ports:
        lst = [r for r in lst if r["port"] in ports]
        if not lst:
            print(f"  没有进程监听这些端口: {sorted(ports)}")
            return 0

    merged = {}
    for r in lst:
        key = (r["port"], r["pid"])
        if key in merged:
            merged[key]["ips"].append(r["ip"])
        else:
            merged[key] = dict(r, ips=[r["ip"]])
    rows = sorted(merged.values(), key=lambda r: (r["port"], r["name"]))

    def bind_of(r):
        ips = set(r["ips"])
        if ips & {"0.0.0.0", "::"}:
            return "全部网卡", "对外"
        if all(i in ("127.0.0.1", "::1") for i in ips):
            return "仅本机", "本机"
        return ", ".join(sorted(ips))[:26], "指定网卡"

    show = rows if args.all else rows[:60]
    print(f"  监听 {len(rows)} 项\n")
    print("  " + pad("端口", 7, "r") + " " + pad("绑定", 18) + " " + pad("暴露", 8)
          + " " + pad("PID", 8, "r") + " " + pad("进程", 22) + " "
          + pad("服务", 18) + "  启动参数 / 路径")
    print("  " + "-" * 150)
    for r in show:
        bind, expo = bind_of(r)
        cmd = r.get("cmdline") or r.get("exe") or "-"
        if dwidth(cmd) > 58:
            cmd = cmd[:40] + " … " + cmd[-14:]
        print("  " + pad(r["port"], 7, "r") + " " + pad(bind, 18) + " " + pad(expo, 8)
              + " " + pad(r["pid"], 8, "r") + " " + pad(r["name"][:22], 22) + " "
              + pad((r.get("service") or "-")[:18], 18) + "  " + cmd)
    if len(rows) > len(show):
        print(f"  … 其余 {len(rows) - len(show)} 项（--all 查看全部）")

    print(f"\n  终止占用者: {cli_cmd('kill', '--port', 8080)}   "
          f"或  {cli_cmd('port', '--port', 8080, '--kill')}（换成实际端口）")

    if args.kill:
        targets = sorted({r["pid"] for r in rows})
        print()
        sub = argparse.Namespace(pid=targets, port=None, target=[], tree=args.tree,
                                 force=False, yes=args.yes, list=False,
                                 verbose=getattr(args, "verbose", False))
        return cmd_kill(sub)
    return 0


def cmd_proc(args):
    if not args.target:
        print(f"  用法: {cli_cmd('proc')} PID或进程名")
        return 1
    rows = _match_procs(args)
    if not rows:
        print("  未匹配到进程")
        return 1

    for r in rows:
        d = metrics.proc_detail(r["pid"])
        if not d:
            print(f"\n  [PID {r['pid']}] {r['name']}  详情读取失败（可能受保护或已退出）")
            continue
        print(f"\n  [PID {d['pid']}] {d['name']}   {d['status']}   "
              f"CPU {d['cpu']:.1f}%   内存 {_human(d['mem'])}（私有 {_human(d['mem_priv'])}）")
        print(f"    路径  : {d['exe'] or '-'}")
        print(f"    命令  : {d['cmdline'] or '-'}")
        if d["cwd"]:
            print(f"    工作目录: {d['cwd']}")
        line = f"    用户  : {d['user'] or '-'}   线程 {d['threads']}   父PID {d['ppid']}"
        if d["started"]:
            line += "   启动 " + time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(d["started"]))
        print(line)
        if d["service"]:
            print(f"    服务  : {d['service']}")
        if d["listening"]:
            print(f"    监听  : {', '.join(d['listening'][:10])}")
        print(f"    连接数: {d['connections']}")
        if d["children"]:
            print("    子进程: " + ", ".join(f"{n}({p})" for p, n in d["children"][:12]))
        if d["pid"] > 4:
            print(f"    终止  : {cli_cmd('kill', d['pid'], '--tree')}")
    return 0


# ───────────────────────────── main ─────────────────────────────

def cmd_mem(args):
    """内存总览 + 可选释放。默认只读，--trim / --purge 才动手。"""
    from . import memtrim

    st = memtrim.status()
    used = max(0, st["total"] - st["avail"])
    print(f"  物理内存: 总 {_human(st['total'])} / 已用 {_human(used)} ({st['load']}%)"
          f" / 可用 {_human(st.get('phys_avail') or st['avail'])}")
    if st.get("standby"):
        print(f"  其中待机缓存: {_human(st['standby'])}（算在「可用」里的缓存部分）")
    print(f"  提交(Commit): {_human(st['commit_used'])} / 上限 {_human(st['commit_limit'])}")
    print(f"  管理员: {'是' if st['admin'] else '否（--purge 需要管理员）'}")

    cands = memtrim.candidates(0)
    if args.only:
        want = set(args.only)
        cands = [c for c in cands if c["pid"] in want]
    print(f"\n  内存占用 TOP {args.top}（≥{args.min_mb:g}MB 的可释放）")
    print(f"  {'进程':<26}{'PID':>7}  {'内存':>9}  说明")
    shown = 0
    for c in cands:
        if shown >= args.top:
            break
        shown += 1
        note = c["blocked"] or ("可释放" if c["rss"] >= args.min_mb * 1024 ** 2 else "占用较小")
        print(f"  {c['name'][:26]:<26}{c['pid']:>7}  {_human(c['rss']):>9}  {note}")

    if not args.trim and not args.purge:
        print("\n  只读模式（未做任何改动）。要真的释放：")
        print(f"    {cli_cmd('mem', '--trim')}          # 释放 ≥{args.min_mb:g}MB 的闲置进程内存")
        print(f"    {cli_cmd('mem', '--trim', '--only', 1234)}   # 只处理某个 PID")
        return 0

    if args.purge:
        if not args.yes:
            print("\n  清空待机缓存会让之后一两分钟读盘变慢，且收益很小。继续请输入 y：", end="")
            if input().strip().lower() not in ("y", "yes"):
                print("  已取消")
                return 0
        res = memtrim.purge_standby()
        print(("  " + res["msg"]) if not res["ok"]
              else f"  {res['msg']}：可用 {_human(res['before'].get('phys_avail', 0))}"
                   f" → {_human(res['after'].get('phys_avail', 0))}")

    if args.trim:
        targets = [c for c in cands
                   if not c["blocked"] and c["rss"] >= args.min_mb * 1024 ** 2]
        if not targets:
            print(f"  没有 ≥{args.min_mb:g}MB 的可释放进程")
            return 0
        if not args.yes:
            print(f"\n  将释放这 {len(targets)} 个进程的工作集（进程不退出，只是把内存交还给系统）。"
                  "继续请输入 y：", end="")
            if input().strip().lower() not in ("y", "yes"):
                print("  已取消")
                return 0
        rows, freed, failed = memtrim.trim([c["pid"] for c in targets])
        for pid, ok, msg, saved in rows:
            name = next((c["name"] for c in targets if c["pid"] == pid), "?")
            print(f"  [{'OK ' if ok else 'BAD'}] {name}({pid})  {msg}"
                  + (f"  {_human(saved)}" if ok else ""))
        print(f"\n  完成：{len(rows) - failed} 个成功，合计释放 {_human(freed)}，{failed} 个失败")
        print("  提醒：释放出来的多半变成系统待机缓存（仍算「可用」），可用数字不一定上涨。")
    return 0


# ───────────────────────────── main ─────────────────────────────

def cmd_lock(args):
    """查谁占着这个文件/文件夹；--close 请它正常退出，--kill 强制结束。"""
    from . import filelock

    target = (args.path or "").strip('"')
    if not os.path.exists(target):
        print(f"  [错误] 路径不存在：{target}")
        return 1
    res = filelock.lockers(target)
    q = '"' + res["path"] + '"'          # 路径常带空格，引用一律加双引号
    print(f"  路径: {res['path']}（{'文件夹' if res['is_dir'] else '文件'}，"
          f"检查了 {res['files_checked']} 个文件）")
    if res["error"]:
        print(f"  [警告] {res['error']}")
    holders = res["holders"]
    if not holders:
        perm = filelock.permission_report(target)
        print("  没有进程占着它。")
        if perm.get("note"):
            print(f"  权限诊断：{perm['note']}")
        for c in perm.get("commands") or []:
            print(f"    {c}")
        print("  提示：没有占用却删不掉，基本都是权限/只读；"
              "上面两条命令在「命令提示符(管理员)」里执行。")
        return 0

    print(f"\n  占用者 {len(holders)} 个")
    print(f"  {'进程':<24}{'PID':>7}  {'类型':<14}{'能正常退出':<10}占用原因")
    for h in holders:
        print(f"  {h['name'][:24]:<24}{h['pid']:>7}  {h['kind']:<14}"
              f"{'能' if h['can_close'] else '没有窗口':<10}{h['reason']}")

    if not (args.close or args.kill):
        print("\n  只读模式。要让它松手：")
        print(f"    {cli_cmd('lock', q, '--close')}   # 最安全：请它自己退出")
        print(f"    {cli_cmd('lock', q, '--kill')}    # 强制结束（会丢未保存数据）")
        print("  另一种办法：按上面列出的进程，手动关掉那个程序。")
        return 0

    pids = [h["pid"] for h in holders]
    if args.kill:
        if not args.yes:
            print(f"\n  将强制结束 {len(pids)} 个进程，没保存的内容会丢。继续请输入 y：", end="")
            if input().strip().lower() not in ("y", "yes"):
                print("  已取消")
                return 0
        ok = bad = 0
        for pid in pids:
            try:
                metrics.psutil.Process(pid).kill()
                ok += 1
            except Exception:
                bad += 1
        print(f"  已强制结束 {ok} 个" + (f"，{bad} 个失败（可能已退出或受保护）" if bad else ""))
        return 0

    sent, no_win = filelock.close_gracefully(pids)
    print(f"  已发送关闭消息 {len(sent)} 个"
          + (f"；{len(no_win)} 个没有窗口，收不到消息" if no_win else ""))
    if sent:
        print("  去那些程序里确认一下（它们会自己问要不要保存），然后再试你的删除/改名。")
    if no_win:
        print(f"  没有窗口的（PID {', '.join(map(str, no_win))}）只能强制结束："
              f"{cli_cmd('lock', q, '--kill')}")
    return 0


def cmd_startup(args):
    """开机自启项：默认只读；--disable / --enable / --undo 才动手。"""
    from . import startup

    if args.undo:
        ok, msg = startup.restore_last()
        print(("  " + msg) if ok else f"  [失败] {msg}")
        return 0 if ok else 1

    its = startup.items()
    if not its:
        print("  没读到任何自启项。")
        return 0

    run_n = sum(1 for i in its if i["can_toggle"] and i["enabled"])
    once_n = sum(1 for i in its if not i["can_toggle"])
    broken = [i for i in its if i["exists"] is False]
    print(f"  共 {len(its)} 项：正在开机运行 {run_n} 项，只跑一次 {once_n} 项，"
          f"已停用 {len(its) - run_n - once_n} 项，断链 {len(broken)} 个")
    print(f"\n  {'状态':<6}{'名称':<30}{'位置':<18}说明")
    for i in its:
        if not i["can_toggle"]:
            state = "一次"
        else:
            state = "启用" if i["enabled"] else "停用"
        print(f"  {state:<6}{i['name'][:30]:<30}{i['source']:<18}{i['note'] or ''}")

    want_off = list(args.disable or [])
    want_on = list(args.enable or [])
    if not want_off and not want_on:
        print("\n  只读模式（未做任何改动）。停用某一项：")
        sample = (broken or its)[0]["name"]
        print(f"    {cli_cmd('startup', '--disable', f'\"{sample}\"')}")
        print("  停用只是标记成「开机不启动」，随时可以 --enable 恢复，不会删注册表。")
        return 0

    # 名称精确匹配优先，其次唯一子串匹配 —— 名称太长不好打全
    def pick(names, on):
        hit, miss = [], []
        for raw in names:
            key = raw.strip().strip('"')
            exact = [i for i in its if i["name"] == key]
            cand = exact or [i for i in its if key.lower() in i["name"].lower()]
            if not cand:
                miss.append(key)
            elif len(cand) > 1 and not exact:
                miss.append(f"{key}（匹配到多个：{', '.join(c['name'] for c in cand[:3])}）")
            else:
                hit.append((cand[0], on))
        return hit, miss

    targets, misses = [], []
    for names, on in ((want_off, False), (want_on, True)):
        h, m = pick(names, on)
        targets += h
        misses += m
    for m in misses:
        print(f"  [没找到] {m}")
    if not targets:
        return 1

    todo = [(i, on) for i, on in targets if i["can_toggle"] and i["enabled"] != on]
    skip = [(i, on) for i, on in targets if not (i["can_toggle"] and i["enabled"] != on)]
    for i, _on in skip:
        print(f"  [跳过] {i['name']}："
              + ("只运行一次，不参与停用" if not i["can_toggle"] else "已经是这个状态"))
    if not todo:
        return 0

    if not args.yes:
        verb = "停用" if not todo[0][1] else "恢复"
        print(f"\n  将{verb} {len(todo)} 项（可随时改回来）。继续请输入 y：", end="")
        if input().strip().lower() not in ("y", "yes"):
            print("  已取消")
            return 0

    ok_n = 0
    for it, on in todo:
        ok, msg = startup.set_enabled(it, on)
        if ok:
            ok_n += 1
            print(f"  [OK ] {it['name']} → {'启用' if on else '停用'}")
        else:
            print(f"  [BAD] {it['name']}：{msg}")
    print(f"\n  完成：成功 {ok_n} 个。改动前都备份了，撤销用："
          f"{cli_cmd('startup', '--undo')}")
    return 0


def cmd_du(args):
    """看一个目录下谁最占地方。只统计，不删任何东西。"""
    from . import diskuse

    if not args.path:
        print("  本地磁盘：")
        for d in diskuse.drives():
            print(f"  {d['letter']} {d['label'][:16]:<16} "
                  f"已用 {_human(d['used'])} / 共 {_human(d['total'])}"
                  f"（{d['used'] * 100 // max(1, d['total'])}%）")
        q = chr(34) + "C:" + chr(92) + chr(34)          # "C:\"
        print(f"\n  看某个盘里谁大：{cli_cmd('du', q)}")
        for j in diskuse.quick_jump()[1:6]:
            print(f"  常用：{cli_cmd('du', chr(34) + j['path'] + chr(34))}   # {j['desc']}")
        return 0

    path = args.path.strip().strip('"')
    if not os.path.isdir(path):
        print(f"  [错误] 不是文件夹：{path}")
        return 1
    min_bytes = int(args.min_mb * 1024 ** 2)
    res = diskuse.children(os.path.normpath(path), budget=args.budget,
                           min_bytes=min_bytes)
    if res["error"]:
        print(f"  [错误] {res['error']}")
        return 1

    print(f"  {res['path']}　共 {len(res['items'])} 项，用时 {res['elapsed']:.1f} 秒"
          + ("（有没算完的，标 ≥ 的是下限）" if res["truncated"] else ""))
    print(f"\n  {'体积':>11}  {'文件数':>9}  名称")
    for it in res["items"][:args.top]:
        mark = "≥" if it["partial"] and not it.get("unscanned") else (
            "?" if it.get("unscanned") else " ")
        size = "没算完" if it.get("unscanned") else f"{mark}{_human(it['size'])}"
        kind = "" if it["is_dir"] else "  (文件)"
        print(f"  {size:>11}  {it['files']:>9,}  {it['name']}{kind}")
    if len(res["items"]) > args.top:
        rest = res["items"][args.top:]
        print(f"  {'另有 %d 项' % len(rest):>11}  {'':>9}  合计 {_human(sum(i['size'] for i in rest))}")
    if res.get("rest"):
        print(f"  （体积小于 {args.min_mb:g}MB 的 {res['rest']['count']} 项未列出，"
              f"合计 {_human(res['rest']['size'])}）")
    first_dir = next((i for i in res["items"] if i["is_dir"]), None)
    if first_dir:
        print("\n  想再往下看，把它的路径接在后面：")
        print(f"    {cli_cmd('du', chr(34) + first_dir['path'] + chr(34))}")
    return 0


def cmd_smart(args):
    """硬盘健康：只读，不修任何东西。"""
    from . import smart

    ds = smart.disks()
    if not ds:
        print("  读不到物理磁盘健康信息（系统太旧或控制器不暴露 SMART）。")
        print("  可以用厂商工具看：三星 Magician、Intel MAS、CrystalDiskInfo。")
        return 0

    print(f"  {'盘符':<8}{'型号':<32}{'类型':<16}{'容量':>10}  {'健康':<10}磨损  温度")
    for d in ds:
        letters = "、".join(d["letters"]) or "—"
        wear = "—" if d["wear"] is None else f"{d['wear']:.0f}%"
        temp = "—" if d["temp"] is None else f"{d['temp']:.0f}℃"
        print(f"  {letters:<8}{d['name'][:32]:<32}{d['media'] + '/' + d['bus']:<16}"
              f"{_human(d['size']):>10}  {d['health']:<10}{wear}  {temp}")

    print()
    bad = 0
    for d in ds:
        sev, why = smart.verdict(d)
        letters = "、".join(d["letters"]) or "未分配"
        if sev == "ok":
            extra = []
            if d["hours"] is not None:
                extra.append(f"通电 {d['hours']:.0f} 小时（约 {d['hours'] / 24 / 365:.1f} 年）")
            if d["predict_fail"] is False:
                extra.append("SMART 未预测故障")
            print(f"  [OK ] {letters} {d['name']}：{why}"
                  + ("；" + "，".join(extra) if extra else ""))
        else:
            bad += 1
            print(f"  [{'!!!' if sev == 'error' else ' ! '}] {letters} {d['name']}：{why}")
        if d["read_err"]:
            print(f"        累计记录 {d['read_err']:.0f} 次读错误（持续增长才说明坏道在扩散）")
        if d["predict_fail"] is None:
            print("        这块盘的 SMART 故障预测读不到（NVMe 常见），不代表它是好的")

    if bad:
        print(f"\n  有 {bad} 块盘需要处理：先备份里面的重要数据，再考虑换盘。"
              "本工具只报告，不会去「修」硬盘。")
    else:
        print("\n  硬盘状态正常。这项只读，不会修改任何 SMART 属性，也不会跑磁盘检查。")
    return 0


def main(argv=None):
    argv = _normalize_args(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)

    if getattr(args, "no_color", False):
        pass          # 文本渲染器自行判断 isatty

    # 旧版「跳板机」留下的第三方账号密码 / 会话 cookie：任何一次运行都顺手清掉
    from .legacy import purge_legacy_secrets
    purge_legacy_secrets()

    handler = {
        "run": cmd_run,
        "list": cmd_list,
        "del-account": cmd_del_account,
        "set-account": cmd_set_account,
        "clean": cmd_clean,
        "import-passwords": cmd_import_passwords,
        "kill": cmd_kill,
        "port": cmd_port,
        "proc": cmd_proc,
        "mem": cmd_mem,
        "lock": cmd_lock,
        "startup": cmd_startup,
        "du": cmd_du,
        "smart": cmd_smart,
    }.get(args.cmd or "run")

    try:
        return handler(args) or 0
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        import traceback
        print(f"[错误] {type(exc).__name__}: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 1
