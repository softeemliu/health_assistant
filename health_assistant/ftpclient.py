"""health_assistant.ftpclient — 轻量 FTP / FTPS 客户端（只用标准库 ftplib）

能做：连服务器、列目录、上传（文件与整个文件夹）、下载（文件与整个文件夹）、
新建目录、重命名、删除。不做断点续传、不做自动重试 —— 出错就把真实原因报上去，
不猜也不假装成功。

三条边界（和项目其它动作一个口径）：
1. **密码只在内存里**：不写配置、不写日志、不进报告。调用方自己别把它 emit 出去。
2. **删除只删用户逐个选中的那几项**，不做递归删 —— FTP 上没有回收站，删了就是没了。
3. **列目录读不到就报错**，不用空列表冒充「这个目录是空的」（那是最容易骗人的假象）。

编码：默认 UTF-8，遇到 `UnicodeDecodeError` 自动退回 GBK 再试一次 ——
老的中文 FTP 服务器（Serv-U / IIS 老版本）基本都是 GBK。
"""

from __future__ import annotations

import ftplib
import os
import posixpath
import re
import socket
import ssl
import time

DEFAULT_PORT = 21


class FtpCancelled(Exception):
    """用户点了「停止」。"""


# ───────────────────────────── 错误人话化 ─────────────────────────────

def friendly_error(exc) -> str:
    """把 ftplib / socket 的异常翻成使用者能懂的句子。"""
    if isinstance(exc, FtpCancelled):
        return "已停止"
    if isinstance(exc, ftplib.error_perm):
        code = str(exc)[:3]
        return {
            "530": "用户名或密码不对（530）",
            "331": "服务器要求密码，但给出的密码是空的",
            "550": "服务器拒绝：文件不存在，或者这个账号没有权限（550）",
            "553": "文件名服务器不接受（可能含非法字符，553）",
            "552": "服务器空间不够了（552）",
            "421": "服务器连接数满了，或者被踢下线了（421）",
        }.get(code, f"服务器拒绝了这个操作：{exc}")
    if isinstance(exc, ftplib.error_temp):
        return f"服务器临时故障，过一会再试：{exc}"
    if isinstance(exc, ftplib.error_proto):
        return f"服务器的回话看不懂（可能对方不是 FTP 服务）：{exc}"
    if isinstance(exc, ftplib.error_reply):
        return f"服务器返回了意外回复：{exc}"
    if isinstance(exc, socket.timeout):
        return "服务器没响应（超时）：地址/端口对不对？防火墙有没有拦？"
    if isinstance(exc, ConnectionRefusedError):
        return "对方拒绝连接：端口可能不是 21，或者 FTP 服务没开"
    if isinstance(exc, socket.gaierror):
        return "地址解析失败：IP 或域名写错了"
    if isinstance(exc, ssl.SSLError):
        return f"加密握手失败（服务器证书不被信任？）：{exc}"
    if isinstance(exc, UnicodeDecodeError):
        return "服务器返回的文件名不是 UTF-8 也不是 GBK，无法识别"
    if isinstance(exc, PermissionError):
        return f"本机拒绝写入：{exc}"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return f"{type(exc).__name__}: {exc}"


# ───────────────────────────── LIST 解析 ─────────────────────────────

_DOS_RE = re.compile(
    r"^(\d{2})-(\d{2})-(\d{2}|\d{4})\s+(\d{1,2}):(\d{2})\s*([AP]M)\s+"
    r"(<DIR>|[\d,]+)\s+(.+)$", re.I)

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}


def _parse_unix(line: str):
    """`drwxr-xr-x 2 u g 4096 Oct 21 15:03 name`"""
    parts = line.split(None, 8)
    if len(parts) < 9 or len(parts[0]) < 10:
        return None
    perms, _n, _u, _g, size, mon, day, hm, name = parts
    if perms[0] not in "-dlcbps":
        return None
    if mon.lower() not in _MONTHS:
        return None
    try:
        size_i = int(size)
    except ValueError:
        return None
    if hm.count(":") == 2:                      # 有些服务器按 ISO 给 HH:MM:SS
        hm = hm[:5]
    try:
        stamp = int(time.mktime(time.strptime(
            f"{mon} {day} {hm}", "%b %d %H:%M")))
    except (ValueError, OverflowError):
        stamp = 0
    is_link = perms[0] == "l"
    disp = name.split(" -> ")[0] if is_link else name
    return {"name": disp, "is_dir": perms[0] == "d", "size": size_i,
            "mtime": stamp, "is_link": is_link, "raw": name}


def _parse_dos(line: str):
    """`10-21-26  03:03PM       <DIR>          name`"""
    m = _DOS_RE.match(line)
    if not m:
        return None
    mm, dd, yy, hh, mi, ap, size, name = m.groups()
    year = int(yy) if len(yy) == 4 else 2000 + int(yy)
    hour = int(hh) % 12 + (12 if ap.upper() == "PM" else 0)
    try:
        stamp = int(time.mktime((year, int(mm), int(dd), hour, int(mi), 0,
                                 0, 1, -1)))
    except (ValueError, OverflowError):
        stamp = 0
    is_dir = size.upper() == "<DIR>"
    return {"name": name.rstrip(), "is_dir": is_dir,
            "size": 0 if is_dir else int(size.replace(",", "")),
            "mtime": stamp, "is_link": False, "raw": line}


def _parse_list_line(line: str):
    if not line or line.startswith("total "):
        return None
    return _parse_unix(line) or _parse_dos(line)


def _mls_time(v) -> int:
    """MLSD 的 modify 事实：`20261021150300` 或带 `.sss`，一律 UTC。"""
    if not v:
        return 0
    s = str(v).split(".")[0]
    try:
        t = time.strptime(s, "%Y%m%d%H%M%S")
        return int(time.mktime(t) - time.timezone)
    except ValueError:
        return 0


# ───────────────────────────── 会话 ─────────────────────────────

class Session:
    """一个 FTP 连接。非线程安全 —— 所有调用都在同一个后台任务里做。"""

    def __init__(self, host, port=DEFAULT_PORT, user="", password="",
                 tls=False, passive=True, timeout=20, verbose=None):
        self.host = str(host or "").strip()
        self.port = int(port or DEFAULT_PORT)
        self.user = str(user or "").strip()
        self.password = password or ""
        self.tls = bool(tls)
        self.passive = bool(passive)
        self.timeout = int(timeout or 20)
        self.encoding = "utf-8"
        self._verbose = verbose or (lambda _m: None)
        self._ftp = None

    # ---- 连接 ----
    def connect(self) -> str:
        if not self.host:
            raise ValueError("还没填服务器地址")
        cls = ftplib.FTP_TLS if self.tls else ftplib.FTP
        ftp = cls()
        ftp.encoding = self.encoding
        ftp.set_pasv(self.passive)
        self._verbose(f"正在连接 {self.host}:{self.port}…")
        ftp.connect(self.host, self.port, timeout=self.timeout)
        user = self.user or "anonymous"
        pwd = self.password if self.user else "anonymous@"
        ftp.login(user, pwd)
        if self.tls:
            ftp.prot_p()                      # 数据通道也加密
            ftp.set_pasv(self.passive)
        self._ftp = ftp
        try:
            ftp.voidcmd("OPTS UTF8 ON")       # 让服务器用 UTF-8 回文件名
        except ftplib.all_errors:
            pass
        self._verbose("已登录")
        return ftp.getwelcome() or ""

    def close(self):
        ftp, self._ftp = self._ftp, None
        if ftp is None:
            return
        try:
            ftp.quit()
        except ftplib.all_errors:
            try:
                ftp.close()
            except Exception:
                pass

    @property
    def connected(self) -> bool:
        return self._ftp is not None

    def _ensure(self):
        if self._ftp is None:
            raise RuntimeError("还没连上服务器")
        return self._ftp

    # ---- 目录 ----
    def pwd(self) -> str:
        return self._ensure().pwd()

    def cwd(self, path: str):
        self._ensure().cwd(path)

    def mkdir(self, name: str):
        self._ensure().mkd(name)

    def rename(self, old: str, new: str):
        self._ensure().rename(old, new)

    def remove_file(self, name: str):
        self._ensure().delete(name)

    def remove_dir(self, name: str):
        """只删空目录 —— 非空服务器会拒绝（550），这正是我们想让它拒绝的。"""
        self._ensure().rmd(name)          # ftplib 里叫 rmd，不是 rmdir

    def listdir(self):
        """列当前目录。返回 [{name,is_dir,size,mtime,is_link}]，出错抛异常。"""
        self._ensure()
        try:
            return self._list_once()
        except UnicodeDecodeError:
            # 老中文服务器是 GBK，换编码再来一次
            self.encoding = "gbk"
            self._ftp.encoding = "gbk"
            self._verbose("文件名不是 UTF-8，已切换成 GBK 再读")
            return self._list_once()

    def _list_once(self):
        ftp = self._ensure()
        try:
            out = []
            for name, facts in ftp.mlsd():
                if name in (".", ".."):
                    continue
                kind = str(facts.get("type", "file")).lower()
                out.append({
                    "name": name,
                    "is_dir": kind in ("dir", "cdir", "pdir"),
                    "size": int(facts.get("size") or 0),
                    "mtime": _mls_time(facts.get("modify")),
                    "is_link": kind == "os.unix=symlink",
                    "raw": "",
                })
            if out:
                return out
        except (ftplib.error_perm, ftplib.error_proto, AttributeError, KeyError):
            pass              # 服务器不认 MLSD，退回 LIST
        lines = []
        ftp.retrlines("LIST", lines.append)
        rows = []
        for ln in lines:
            d = _parse_list_line(ln)
            if d and d["name"] not in (".", ".."):
                rows.append(d)
        return rows

    # ---- 上传 ----
    def upload(self, local_paths, progress=None, cancel=None) -> dict:
        """把本机文件/文件夹传到当前远程目录。返回 {files,bytes,total,failed}。"""
        ftp = self._ensure()
        base = ftp.pwd()
        plan = []          # [(本地绝对路径 | None, 远程相对路径, 字节数)]
        for lp in local_paths:
            lp = os.path.abspath(lp)
            if os.path.isdir(lp):
                root_name = os.path.basename(lp.rstrip("\\/")) or "newdir"
                has_any = False
                for cur, _dirs, files in os.walk(lp):
                    rel = os.path.relpath(cur, lp).replace("\\", "/")
                    rel = root_name if rel == "." else f"{root_name}/{rel}"
                    for fn in files:
                        full = os.path.join(cur, fn)
                        try:
                            size = os.path.getsize(full)
                        except OSError:
                            size = 0
                        plan.append((full, f"{rel}/{fn}", size))
                        has_any = True
                    if not files:
                        plan.append((None, rel, 0))     # 空目录也要建出来
                        has_any = True
                if not has_any:
                    plan.append((None, root_name, 0))
            elif os.path.isfile(lp):
                plan.append((lp, os.path.basename(lp), os.path.getsize(lp)))
            else:
                plan.append((lp, os.path.basename(lp), 0))

        total = sum(p[2] for p in plan)
        done = 0
        ok = 0
        failed = []
        for local, rel, size in plan:
            if cancel is not None and cancel():
                raise FtpCancelled()
            try:
                if local is None:                 # 空目录：把目录本身建出来
                    self._ensure_dir(rel)
                    continue
                self._ensure_dir(posixpath.dirname(rel))
                state = {"n": 0}

                def _cb(chunk, _rel=rel, _base=done, _state=state):
                    _state["n"] += len(chunk)
                    if progress:
                        progress(min(_base + _state["n"], max(total, 1)),
                                 max(total, 1), _rel)

                with open(local, "rb") as fh:
                    ftp.storbinary(f"STOR {rel}", fh, 64 * 1024, _cb)
                done += state["n"]
                ok += 1
            except FtpCancelled:
                raise
            except (OSError, ftplib.all_errors) as exc:
                failed.append((rel, friendly_error(exc)))
            finally:
                try:
                    ftp.cwd(base)
                except ftplib.all_errors:
                    pass
        return {"files": ok, "bytes": done, "total": total, "failed": failed}

    def _ensure_dir(self, rel_dir: str):
        """按层次建远程目录（已存在就跳过），结束后回到原目录。"""
        if not rel_dir or rel_dir in (".", "/"):
            return
        ftp = self._ensure()
        base = ftp.pwd()
        try:
            for part in [p for p in rel_dir.split("/") if p and p != "."]:
                try:
                    ftp.mkd(part)
                except ftplib.error_perm:
                    pass                     # 多半是「已存在」
                ftp.cwd(part)
        finally:
            ftp.cwd(base)

    # ---- 下载 ----
    def download(self, remote_names, local_dir, progress=None, cancel=None) -> dict:
        """把远程选中的项下到本机 local_dir。返回 {files,bytes,total,failed}。"""
        ftp = self._ensure()
        base = ftp.pwd()
        plan = []                      # [(远程相对路径, 字节数)]
        try:
            for name in remote_names:
                self._walk_remote(name, name, plan, 0)
        finally:
            ftp.cwd(base)

        total = sum(p[1] for p in plan)
        done = 0
        ok = 0
        failed = []
        os.makedirs(local_dir, exist_ok=True)
        for rel, size in plan:
            if cancel is not None and cancel():
                raise FtpCancelled()
            target = os.path.join(local_dir, rel.replace("/", os.sep))
            try:
                if rel.endswith("/"):                 # 空目录
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                with open(target, "wb") as fh:
                    def _sink(chunk, _rel=rel, _fh=fh, _base=done):
                        nonlocal done
                        _fh.write(chunk)
                        done += len(chunk)
                        if progress:
                            progress(min(done, max(total, 1)), max(total, 1), _rel)
                    ftp.retrbinary(f"RETR {rel}", _sink, 64 * 1024)
                ok += 1
            except FtpCancelled:
                raise
            except (OSError, ftplib.all_errors) as exc:
                failed.append((rel, friendly_error(exc)))
        return {"files": ok, "bytes": done, "total": total, "failed": failed}

    def _walk_remote(self, name, rel, plan, depth):
        """递归收集（列表已经在本目录里，逐层 cwd 进去）。"""
        if depth > 16:
            return
        ftp = self._ensure()
        try:
            entries = {e["name"]: e for e in self.listdir()}
        except ftplib.all_errors:
            plan.append((rel, 0))
            return
        e = entries.get(name)
        if e is None:
            plan.append((rel, 0))          # 找不到也让服务器去报错，别自己编结论
            return
        if not e["is_dir"]:
            plan.append((rel, e["size"]))
            return
        base = ftp.pwd()
        try:
            ftp.cwd(name)
            subs = self.listdir()
            if not subs:
                plan.append((rel + "/", 0))     # 空目录，下载时建出来
            for sub in subs:
                self._walk_remote(sub["name"], f"{rel}/{sub['name']}", plan,
                                  depth + 1)
        finally:
            try:
                ftp.cwd(base)
            except ftplib.all_errors:
                pass


def probe(host, port=DEFAULT_PORT, timeout=5) -> dict:
    """不登录，只看这个地址的 21 端口通不通、回什么。用于「连不上」时给线索。"""
    out = {"ok": False, "banner": "", "error": ""}
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
        out["banner"] = data.decode("utf-8", "replace").strip()
        out["ok"] = out["banner"].startswith("220")
        if not out["ok"]:
            out["error"] = f"端口通的，但对方不是 FTP 服务（回话：{out['banner'][:60]}）"
    except Exception as exc:
        out["error"] = friendly_error(exc)
    return out
