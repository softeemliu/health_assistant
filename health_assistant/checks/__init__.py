"""
health_assistant.checks — 内置巡检项包

导入本包即完成所有内置检查的注册（@check 装饰器副作用）。
新增检查：在 checks/ 下加一个 .py，写 @check 装饰的函数，然后在这里 import。
"""

from . import cleanup, network, ops, profile, security, system     # noqa: F401  导入即注册

__all__ = ["system", "network", "ops", "security", "cleanup", "profile"]
