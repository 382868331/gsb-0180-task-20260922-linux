"""输入校验原语：非法输入抛 ValidationError，不静默纠正。

规则（全库统一）：
- 整数参数只接受精确 int；bool 一律拒绝；float（含 3.0）一律拒绝，
  因此 NaN/Infinity 在类型层即被拒绝，绝不进入比较。
- IPv4 只接受严格点分十进制 "a.b.c.d"，每段 0..255，无前导零、无空白。
"""

from __future__ import annotations

import ipaddress

from .errors import ValidationError


def check_int(value: object, name: str, *, minimum: int, maximum: int) -> int:
    """校验严格整数并返回之。bool / float / NaN / Infinity 均拒绝。"""
    if isinstance(value, bool):
        raise ValidationError(f"{name} must be int, got bool {value!r}")
    if isinstance(value, float):
        # 显式分支：NaN/Infinity 与有限 float 给出可区分的定位信息。
        if value != value:  # NaN
            raise ValidationError(f"{name} must be a finite int, got NaN")
        if value in (float("inf"), float("-inf")):
            raise ValidationError(f"{name} must be a finite int, got {value!r}")
        raise ValidationError(
            f"{name} must be int, got float {value!r} (no silent coercion)"
        )
    if not isinstance(value, int):
        raise ValidationError(
            f"{name} must be int, got {type(value).__name__} {value!r}"
        )
    if not (minimum <= value <= maximum):
        raise ValidationError(
            f"{name}={value} out of range [{minimum}, {maximum}]"
        )
    return value


def check_port(value: object, name: str) -> int:
    """UDP 端口：1..65535 的严格整数。"""
    return check_int(value, name, minimum=1, maximum=65535)


def check_ipv4(value: object, name: str) -> str:
    """严格点分十进制 IPv4 地址。"""
    if not isinstance(value, str):
        raise ValidationError(
            f"{name} must be str IPv4, got {type(value).__name__} {value!r}"
        )
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValidationError(f"{name} invalid IPv4 address {value!r}: {exc}") from exc
    if str(addr) != value:
        # 前导零等非规范写法：拒绝而非静默规范化。
        raise ValidationError(
            f"{name}={value!r} is not canonical dotted-decimal ({addr})"
        )
    return value
