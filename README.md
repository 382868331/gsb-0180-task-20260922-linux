# adnat —— 地址依赖 NAT 端点生命周期（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟地址依赖（address-dependent）映射与
过滤的 UDP NAT。**纯状态库，不发任何网络包**；核心、测试、演示全部离线。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

```bash
python -m unittest discover -s tests -v   # 必要测试（契约 + 差分）
python demo.py                            # 固定输入演示，秒级完成
```

## 模型与契约

- **出站 key** = `(内网IP, 内网端口, 目的IP, 目的端口)`。同一内网端点访问
  不同目的产生**不同映射**（地址依赖）。公网 IP 固定（`NATConfig.public_ip`）。
- **外端口**：从给定有限池 `external_ports` 中选**最小空闲**端口
  （池可乱序给出，内部升序去重）。
- **入站过滤**：包必须命中某映射的外端口，且源端点 == 该映射记录的对端，
  目的 IP == 公网 IP，否则丢弃。
- **内部回转（hairpin）**：内部主机经对方的公网映射互访时，
  `translate_outbound` 识别"目的 IP == 公网 IP"的内部包。必须同时存在
  两条活跃映射（源主机 -> 目的公网端点；目的外端口属主 -> 源公网端点），
  且**两侧 generation 分别校验通过、互为记录对端**，才把五元组改写为
  `(公网IP, 源外端口) -> 目的内部端点`；回复方向同理（两侧互换）。
  任何一侧映射缺失/过期/代数不符/对端不符都丢弃，且不刷新任何映射。
  由 `NATConfig.hairpin=False` 可关闭，关闭时返回 `HAIRPIN_DISABLED`。
- **时间**：显式整数时钟。`advance(seconds)` 推进；每次公开调用先按当前
  时钟做 housekeeping（过期回收、隔离到期释放）再处理请求。时钟只增不减。
  映射在 `now >= expires_at` 时过期（**边界即死**）；成功改写的包刷新
  `expires_at = now + lifetime`。
- **隔离 Q**：映射过期或被 `release` 后，其端口隔离 `quarantine` 个时间
  单位，`now >= released_at + Q` 才可复用。
- **generation**：每条映射创建时取全局单调递增序号（从 1 开始）。合成包
  可携带 `generation`；与映射当前值不一致即判**迟到包**丢弃
  （`STALE_GENERATION`）。`generation=0` 表示不参与校验。
- **批量原子性**：`allocate_many` 先完成全部校验与容量规划（纯函数），
  全部可满足才一次性提交；失败时**状态与调用前完全一致**（含时钟不动）。
- **预算与无解分开**：容量检查按端口升序进行，最多检查 `search_budget`
  个端口。预算耗尽抛 `SearchBudgetExhaustedError`（未扫描全池，**不**
  代表无解）；全池扫描仍不够抛 `PortExhaustionError`（**证明无解**）。

## 公开接口

```python
from adnat import (
    AddressDependentNAT, NATConfig, Endpoint, Packet,
    AllocationRequest, AllocationResult, TranslationResult,
    Mapping, FiveTuple, DropReason,
    NATError, ValidationError, PortExhaustionError,
    SearchBudgetExhaustedError,
)

nat = AddressDependentNAT(NATConfig(
    public_ip="203.0.113.7",
    external_ports=(6100, 6101, 6102),
    lifetime=300,        # 映射空闲存活（整数时间单位），>= 1
    quarantine=60,       # 端口释放后隔离时长 Q，>= 0
    search_budget=None,  # 单次分配最多检查的端口数；None = 池大小（全池扫描）
    hairpin=True,        # 是否允许内部主机经公网映射互访（内部回转）
))

nat.allocate(internal: Endpoint, remote: Endpoint, *, at: int | None = None)
    -> AllocationResult
nat.allocate_many(requests: list[AllocationRequest], *, at: int | None = None)
    -> list[AllocationResult]            # 原子：全成功或整体回滚
nat.translate_outbound(packet: Packet, *, at: int | None = None)
    -> TranslationResult                 # 不隐式建映射；无映射丢弃
nat.translate_inbound(packet: Packet, *, at: int | None = None)
    -> TranslationResult
nat.release(key: tuple, *, at: int | None = None) -> bool   # 不存在返回 False
nat.advance(seconds: int) -> list[key]                      # 返回本次过期的 key
nat.get_mapping(key) -> Mapping | None
nat.snapshot_mappings() -> list[Mapping]
nat.quarantined_ports() -> dict[int, int]
nat.stats() -> dict[str, int]
nat.now -> int
```

`TranslationResult.accepted=True` 时 `rewritten` 为改写后的 `FiveTuple`
（UDP，protocol=17）；否则 `reason` 为 `DropReason` 之一：
`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` / `DEST_MISMATCH` /
`HAIRPIN_DISABLED`。

`Packet(src, dst, generation=0, peer_generation=0, payload=b"")` 中
`peer_generation` 为回转包"目的侧公网映射"的观测代数，与源侧的
`generation` 分别校验、互不混用；0 表示该侧不校验。目标映射过期、
端口被重新分配给其他内部设备时，迟到回转包因目的侧代数不符
（`STALE_GENERATION`）或对端不符（`PEER_MISMATCH`）被丢弃，
绝不会送到新设备。

## 错误语义

所有异常继承 `NATError`：

| 异常 | 含义 | 状态影响 |
|---|---|---|
| `ValidationError` | 非法输入（类型/取值/越界/时钟回退/批内重复 key 等） | 在任何变更之前抛出，状态不变 |
| `PortExhaustionError` | 全池扫描后容量不足（证明无解），带 `needed/available/pool_size` | 整体回滚，状态不变 |
| `SearchBudgetExhaustedError` | 搜索预算耗尽（未证明无解），带 `budget/inspected/needed/found` | 整体回滚，状态不变 |

输入校验规则（全库统一）：整数参数只接受精确 `int`；**`bool` 一律拒绝**；
`float`（含 `3.0`）一律拒绝，因此 **NaN/Infinity 在类型层即被拒绝**；
IPv4 只接受规范点分十进制（无前导零）。错误消息均带字段名与实收值，
可定位；不做任何静默纠正。

## 输入上限

| 参数 | 上限 |
|---|---|
| 端口 | 1..65535 |
| 端口池大小 | 1..65535（`MAX_POOL_SIZE`），且无重复 |
| 单批分配请求数 | `MAX_BATCH_REQUESTS` = 65535，且批内 key 不重复 |
| 时间类整数（`at`/`advance`/`lifetime`/`quarantine` 等） | 0..2^63-1（`MAX_TIME`），且 `now + lifetime` 不得溢出 |
| `generation` | 0..2^63-1 |

## 精度说明（误差口径）

本库**不产生浮点结果**：所有计算（端口选择、过期判定、隔离判定、
generation 比较）均为精确整数运算，比较采用严格不等式
（`now >= expires_at` 过期、`now >= released_at + Q` 解除隔离），
边界行为由 `tests/test_contract.py` 中的边界用例逐点固定，无容差。

## 设计取舍

- **纯函数规划 + 一次性提交**：批量分配把"校验/容量规划"与"状态提交"
  分开，从结构上保证失败即零副作用，而非事后补偿回滚。
- **每次调用做 housekeeping**：任何公开操作都会先把时钟推进到本次
  请求时刻（默认当前时钟），保证"过期即不可见"不依赖显式 `advance`；
  `advance` 仍是驱动时间的主要入口并返回过期清单。
- **复用不刷新**：`allocate` 命中已有映射只复用，不刷新过期时间；
  只有成功的包改写刷新（模拟真实流量保活）。
- **`generation=0` 豁免**：不知道代号的调用方（如首包）可传 0 跳过
  迟到校验，避免强制所有调用方跟踪代号。
- **回转复用既有映射**：hairpin 不新建任何映射、不放松任何过滤；它要求
  两侧 key 在普通出站分配阶段就已存在且互相指向。成功回转同时刷新两侧
  映射的过期时间（双向都视为真实流量保活）；失败不刷新任何一侧。
- **回转双代数**：`generation` 与 `peer_generation` 分属源/目的两条映射，
  不允许用一个代数同时代表两侧，从结构上防止旧回复串到新设备。
- **参考实现独立**：`tests/reference_nat.py` 只用字典/元组重写同一契约，
  不导入被测核心；差分测试逐操作比对公开结果与规范化状态签名。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，并支持
  同一套映射/过滤规则上的内部回转（hairpin）；不含端口依赖/锥形 NAT、
  ALG、分片、ICMP 等行为。回转不改写 payload，不做 NAT ALG。
- 单实例、单线程；状态只在内存中，无持久化。
- 端口分配为"最小空闲"策略的线性扫描，复杂度 O(池大小)；
  本题上限（65535）下足够。
- 出站方向无映射时**丢弃**而非隐式建映射（建映射必须显式 `allocate`）。
- 时钟接近 `MAX_TIME` 时（`now + lifetime` 溢出）抛 `ValidationError`。

## 目录

```
adnat/            本题库（可导入）
  __init__.py     公开导出
  model.py        冻结数据结构 + NATConfig
  errors.py       异常层级
  core.py         AddressDependentNAT 核心
  _validate.py    输入校验原语
tests/
  test_contract.py      契约测试（手工期望值）
  test_differential.py  差分测试（核心 vs 独立字典参考）
  reference_nat.py      独立字典参考实现（测试 oracle）
demo.py           固定输入演示
```
