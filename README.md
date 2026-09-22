# nat_sim — 合成 UDP NAT 状态库（地址依赖端点生命周期）

纯 Python 标准库实现的**合成**地址依赖 NAT(endpoint-dependent mapping +
endpoint-dependent filtering）状态表。不发送、不接收任何真实网络包，
只维护状态并改写合成五元组。全部离线运行。

- Python 版本：**3.14.7**（仅标准库，无第三方依赖，`requirements.txt` 为空说明）
- 平台：Linux 原生；安装 Python 后无需任何额外安装

## 接口

```python
from nat_sim import NatConfig, NatTable, DropReason, CapacityError, ValidationError

table = NatTable(NatConfig(
    public_ip="203.0.113.7",      # 固定公网 IP（str，须为合法 IP）
    port_pool=(40000, 40001),     # 有限外端口池：range 或 int 可迭代，非空、无重复
    mapping_timeout=30,           # T：映射空闲寿命，整数 >= 1
    quarantine_time=10,           # Q：端口释放后隔离时长，整数 >= 0
))
```

| 方法 | 语义 |
|---|---|
| `advance(seconds)` | 显式整数时钟前进（`seconds >= 0`)。过期 `expires_at <= now` 的映射，其端口进入隔离至 `now + Q`；同时释放隔离已结束（`<= now`）的端口。 |
| `outbound(ip, port, dst_ip, dst_port)` | 出站改写。key=（内网IP，端口，目的IP，端口）。命中已有映射则复用并刷新过期时间；否则分配池中**最小空闲**外端口。池满不抛异常，返回 `ok=False, reason=POOL_EXHAUSTED`。 |
| `outbound_batch(packets)` | 批量出站，**原子**：先校验全部输入，再核算新映射所需端口数；容量不足抛 `CapacityError`，表状态完全不变（先检查后应用，结构上即全批回滚）。 |
| `inbound(src_ip, src_port, ext_port, generation)` | 入站过滤+改写。依次检查：外端口有活跃映射（否则 `NO_MAPPING`)→ 对端精确匹配（否则 `PEER_MISMATCH`，地址依赖过滤）→ generation 一致（否则 `STALE_GENERATION`，迟到包）。 |
| `now` / `snapshot()` | 当前整数时钟 / 只读结构视图（映射、空闲端口、隔离表）。 |

成功时返回改写后五元组 `FiveTuple(protocol="UDP", src_ip, src_port, dst_ip, dst_port)`:
出站为 `(UDP, 公网IP, 外端口, 目的IP, 目的端口)`，入站为 `(UDP, 对端IP, 对端口, 内网IP, 内网端口)`。

## 契约要点（边界语义）

- 映射在 `now < expires_at` 时存活，`now >= expires_at` 时过期（`expires_at = 刷新时刻 + T`)。
- 出站命中会刷新过期时间；入站不刷新（设计取舍，见下）。
- 端口隔离期 `now < quarantine_until` 内不可分配，`now >= quarantine_until` 释放。
- 每个外端口有单调递增 generation 计数器，每次分配 +1；映射记录分配时的值。
- 入站检查顺序固定为 NO_MAPPING → PEER_MISMATCH → STALE_GENERATION。

## 错误语义与输入上限

- 整数参数拒绝 `bool`、拒绝一切非 `int` 类型（`float` 不做静默截断）;`NaN`/`Infinity` 显式拒绝。
- IP 必须是合法 IP 字符串（`ipaddress` 校验）；端口范围 `[0, 65535]`。
- `mapping_timeout >= 1`,`quarantine_time >= 0`,`advance` 步长 `>= 0`；端口池非空且无重复（重复拒绝而非静默去重）。
- 所有非法输入抛 `ValidationError`（同时是 `ValueError`)，消息中含参数名与实参值，可定位；不做任何静默纠正。
- 容量不足：`outbound_batch` 抛 `CapacityError` 且**无任何部分变更**；单条 `outbound` 返回 `ok=False` 结果对象而非异常。
- 输入规模上限：端口数受 `[0,65535]` 限制（池最大 65536 项）；映射数受池容量限制；时间为非负 `int`(Python 任意精度）。

## 设计取舍

- **先检查后应用**实现批量原子性：容量核算不依赖回滚日志，失败路径天然零副作用。
- generation 挂在**外端口**而非全局：端口复用即 bump，精确刻画"迟到包属于上一世"。
- 入站不刷新映射寿命：简化契约，使超时边界只由出站活动驱动，便于确定性测试。
- 单条出站池满返回结果对象而非异常：单包失败是正常转发事件；批量失败才是契约级错误。

## 已知限制

- 仅实现本题契约的有限子集：UDP、地址依赖映射+过滤、固定公网 IP、显式时钟；**不宣称**兼容 RFC 4787/5382 等完整行业标准，无 hairpin、无并发安全、无真实 sockets。
- 时间只前进不倒退；无显式删除映射接口（只能等超时）。
- 本库无浮点输入/输出，**误差口径：不适用**——所有结果为整数/字符串/枚举，精确相等，不存在浮点容差问题。

## 运行

```bash
python -m unittest discover -s tests -v   # 单元测试 + 对独立字典参考的差分测试
python demo.py                            # 固定输入演示（< 8 秒，无 sleep）
```

`tests/reference.py` 是直接从题面契约书写的独立 dict 参考模型，**不 import 被测核心**;
`TestDifferentialAgainstReference` 用固定种子随机操作序列逐条比对双方输出与最终结构。
