"""health_assistant.legacy — 清掉旧版本留在本机的敏感文件。

背景（3.7.2，安全考虑）：3.6.0 ~ 3.7.1 的「跳板机」页会把第三方系统（JumpServer）
的账号密码用 DPAPI 加密存在本机，还会把内嵌浏览器的会话 cookie 持久化到 profile
目录。功能整体移除之后，这些文件不该继续留在使用者机器上，所以要主动清掉。

只处理下面三个**确切路径**，别的一律不碰（运行日志、清理台账、注册表清理备份、
凭据删除备份都保留）：

· %LOCALAPPDATA%\\health_assistant\\jumpserver-accounts.json   第三方账号密码（DPAPI 密文）
· %LOCALAPPDATA%\\health_assistant\\webview\\                  内嵌浏览器 cookie / 缓存
· %APPDATA%\\health_assistant\\QtWebEngine\\                   旧版 WebEngine 默认 profile

清理是幂等的：没有就不动，删不掉就静默放弃（权限 / 被占用都不该拦住工具启动）。
"""

from __future__ import annotations

import os
import shutil

__all__ = ["legacy_paths", "purge_legacy_secrets"]


def _localappdata():
    return os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")


def _appdata():
    return os.environ.get("APPDATA") or os.path.expanduser("~")


# 两个目录名都要查：
#   · "pcinspect" 是 4.16 改名**之前**的名字 —— 那些敏感文件正是那时候留下的；
#   · "health_assistant" 是现在的名字 —— 启动时的迁移会把老目录内容复制过来。
# 只查一个就会漏：改名后光清新目录，老目录里的账号密文还躺在盘上。
_DIR_NAMES = ("health_assistant", "pcinspect")


def legacy_paths():
    """旧版留下的敏感路径（存在才返回）。"""
    out = []
    for name in _DIR_NAMES:
        local = os.path.join(_localappdata(), name)
        roaming = os.path.join(_appdata(), name)
        for p in (os.path.join(local, "jumpserver-accounts.json"),   # 文件
                  os.path.join(local, "webview"),                    # 目录
                  os.path.join(roaming, "QtWebEngine")):             # 目录
            if os.path.exists(p) and p not in out:
                out.append(p)
    return out


def purge_legacy_secrets(dry_run=False):
    """删除旧版遗留的账号密码 / 会话文件，返回已删（或将要删）的路径列表。"""
    gone = []
    for path in legacy_paths():
        if dry_run:
            gone.append(path)
            continue
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
        except OSError:
            continue
        if not os.path.exists(path):
            gone.append(path)
    return gone
