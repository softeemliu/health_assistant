"""health_assistant.smart — 硬盘健康（只读，只报告）

为什么单独做
    「电脑慢」查 CPU/内存/磁盘占用都不高时，下一个怀疑对象就是硬盘快坏了：
    机械盘有坏道会卡顿、SSD 磨损到寿命末期会掉速甚至只读。这些数字系统里有，
    但要看得到得开 CrystalDiskInfo 或者一层层点进 WMI —— 普通用户不会去。

数据来源（都是系统自带，不装任何东西）
    1. Get-PhysicalDisk            → 型号 / 类型 / 容量 / HealthStatus（系统自己的判定）
    2. Get-StorageReliabilityCounter → 磨损百分比 / 温度 / 通电小时数 / 读写错误计数
    3. MSStorageDriver_FailurePredictStatus → SMART 的「预测即将故障」标志
    4. Get-Partition               → 这块盘上挂着哪些盘符（C: / D: …）

硬边界
    完全不写：不调任何 SMART 属性修改、不跑 chkdsk、不「修复」坏道。
    坏了就是坏了，这个工具只负责让你**提前知道**，该换盘换盘、该备份备份。
    温度/通电时间这两项，SATA 盘和 NVMe 盘报的字段不一样 —— 有的给温度不给小时，
    有的反过来，缺的就是 None，界面上写「—」，不猜、不用 0 冒充。
"""

from __future__ import annotations

import json

from .core import run_cmd

__all__ = ["disks", "verdict", "WEAR_WARN", "WEAR_ERROR", "TEMP_WARN"]

WEAR_WARN = 80          # 磨损到 80% 起提醒
WEAR_ERROR = 90         # 90% 以上基本该换了
TEMP_WARN = 70          # 硬盘温度（摄氏度）

_MEDIA = {
    "SSD": "固态硬盘", "HDD": "机械硬盘", "SCM": "存储级内存",
    "Unspecified": "未标注",
}

_PS_HEAD = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


def _ps(script, timeout=25):
    """跑一段 PowerShell，返回解析后的 JSON（失败返回 None）。"""
    # 输出统一 UTF-8：中文型号名用默认 OEM 代码页读会乱码
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script
    rc, out = run_cmd(_PS_HEAD + [full], timeout=timeout, encoding="utf-8")
    if rc != 0 and not out.strip():
        return None
    out = out.strip()
    if not out:
        return None
    # PowerShell 偶尔在前面吐警告，从第一个 { 或 [ 开始截
    for i, ch in enumerate(out):
        if ch in "{[":
            out = out[i:]
            break
    try:
        return json.loads(out)
    except ValueError:
        return None


_SCRIPT = """
$ErrorActionPreference='SilentlyContinue';
$basic=@(Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,MediaType,BusType,Size,HealthStatus,OperationalStatus);
$rel=@(Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId,Wear,Temperature,PowerOnHours,ReadErrorsTotal,WriteErrorsTotal);
$fail=@(Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object InstanceName,PredictFailure,Reason);
$part=@(Get-Partition | Where-Object { $_.DriveLetter } | Select-Object DiskNumber,DriveLetter,Size);
ConvertTo-Json -InputObject ([pscustomobject]@{basic=$basic;rel=$rel;fail=$fail;part=$part}) -Depth 4 -Compress
"""


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _num(x):
    try:
        if x is None:
            return None
        return float(x)
    except (TypeError, ValueError):
        return None


def _norm(s):
    """只留字母数字并转小写 —— 用来把 'Samsung SSD 870 EVO 500GB' 和
    SMART 实例名里的 'Prod_SSD_870_EVO_500G' 对上（型号常被截短、空格变下划线）。"""
    return "".join(ch for ch in str(s or "").lower() if ch.isalnum())


def _match_fail(name, fails):
    """在 SMART 故障预测列表里找这块盘。找不到返回 None（不是「没故障」）。"""
    key = _norm(name)
    for f in fails:
        inst = str(f.get("InstanceName") or "")
        prod = ""
        for seg in inst.split("&"):
            if seg.lower().startswith("prod_"):
                # 'Prod_SSD_870_EVO_500G\\4611742ca2&0&040000_0' —— 反斜杠后面是实例号，去掉
                prod = seg[5:].split("\\")[0]
                break
        cand = _norm(prod or inst)
        if not cand:
            continue
        # 型号可能被截短：短的那边是长的那边的子串就算同一块
        if cand in key or key in cand:
            return bool(f.get("PredictFailure"))
    return None


def disks():
    """所有物理磁盘的健康信息。读不到返回 []。

    每项字段：
      name / media / bus / size / health / operational
      wear(%) / temp(℃) / hours / read_err / write_err
      predict_fail / letters / note
    """
    data = _ps(_SCRIPT, timeout=30)
    if not isinstance(data, dict):
        return []

    basic = _as_list(data.get("basic"))
    rel = {str(r.get("DeviceId")): r for r in _as_list(data.get("rel"))}
    fails = _as_list(data.get("fail"))
    parts = _as_list(data.get("part"))

    letters = {}
    for p in parts:
        dn = str(p.get("DiskNumber"))
        ch = p.get("DriveLetter")
        if ch:
            letters.setdefault(dn, []).append(f"{ch}:")
    for k in letters:
        letters[k].sort()

    # 预测故障按型号名匹配 InstanceName（里面带 Prod_XXX）
    out = []
    for b in basic:
        did = str(b.get("DeviceId"))
        name = str(b.get("FriendlyName") or "未知磁盘")
        r = rel.get(did) or {}
        temp = _num(r.get("Temperature"))
        # SMART 报 0 度等于没报（运行的硬盘不可能是 0℃），别当成「凉快」
        if temp is not None and temp <= 0:
            temp = None
        out.append({
            "id": did,
            "name": name,
            "media": _MEDIA.get(str(b.get("MediaType")), str(b.get("MediaType") or "—")),
            "bus": str(b.get("BusType") or "—"),
            "size": _num(b.get("Size")) or 0,
            "health": str(b.get("HealthStatus") or "—"),
            "operational": str(b.get("OperationalStatus") or "—"),
            "wear": _num(r.get("Wear")),
            "temp": temp,
            "hours": _num(r.get("PowerOnHours")),
            "read_err": _num(r.get("ReadErrorsTotal")),
            "write_err": _num(r.get("WriteErrorsTotal")),
            "predict_fail": _match_fail(name, fails),
            "letters": letters.get(did, []),
        })
    out.sort(key=lambda d: (d["letters"][:1] or ["ZZ"])[0])
    return out


def verdict(d):
    """单块盘的结论：("ok"/"warn"/"error", 一句话)。"""
    if d.get("predict_fail"):
        return "error", "SMART 已经预测这块盘即将故障 —— 先备份数据，尽快换"
    if d.get("health") not in ("Healthy", "—", "Unknown"):
        return "error", f"系统判定这块盘状态异常（{d['health']}）"
    if d.get("operational") not in ("OK", "—", "Unknown"):
        return "error", f"这块盘运行状态不正常（{d['operational']}）"
    wear = d.get("wear")
    if wear is not None:
        if wear >= WEAR_ERROR:
            return "error", f"磨损已经用到 {wear:.0f}%，接近寿命上限（{100 - wear:.0f}% 余量）"
        if wear >= WEAR_WARN:
            return "warn", f"磨损到 {wear:.0f}%，余量 {100 - wear:.0f}%，该准备换了"
    temp = d.get("temp")
    if temp is not None and temp >= TEMP_WARN:
        return "warn", f"温度 {temp:.0f}℃，偏高（散热要注意）"
    return "ok", "各项指标正常"
