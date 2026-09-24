# adnat —— 地址依赖 NAT 端点生命周期 + 主备复制（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟地址依赖（address-dependent）映射与
过滤的 UDP NAT，并为映射生命周期提供有序记录、备用重放与栅栏接管。
**纯状态库，不发任何网络包**；核心、测试、演示全部离线。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

```bash
python -m unittest discover -s tests -v   # 必要测试（契约 + 差分 + 复制接管）
python demo.py                            # 固定输入演示（含复制与接管），秒级完成
```

## 模型与契约

- **出站 key** = `(内网IP, 内网端口, 目的IP, 目的端口)`。同一内网端点访问
  不同目的产生**不同映射**（地址依赖）。公网 IP 固定（`NATConfig.public_ip`）。
- **外端口**：从给定有限池 `external_ports` 中选**最小空闲**端口
  （池可乱序给出，内部升序去重）。
- **入站过滤**：包必须命中某映射的外端口，且源端点 == 该映射记录的对端，
  目的 IP == 公网 IP，否则丢弃。
- **时间**：显式整数时钟。`advance(seconds)` 推进；每次公开调用先按当前
  时钟做 housekeeping（过期回收、隔离到期释放）再处理请求。时钟只增不减。
  映射在 `now >= expires_at` 时过期（**边界即死**）；成功改写的包刷新
  `expires_at = now + lifetime`。
- **隔离 Q**：映射过期或被 `release` 后，其端口隔离 `quarantine` 个时间
  单位。过期映射的端口自 `expires_at`（逻辑死亡时刻）起隔离；显式
  `release` 的端口自释放时刻起隔离；`now >= 起始时刻 + Q` 才可复用。
- **generation**：每条映射创建时取全局单调递增序号（从 1 开始）。合成包
  可携带 `generation`；与映射当前值不一致即判**迟到包**丢弃
  （`STALE_GENERATION`）。`generation=0` 表示不参与校验。
- **有序记录（journal）**：映射的**创建**（`allocate` 新建）、**刷新**
  （成功的 `translate_*`）、**释放**（`release`）各自追加一条
  `JournalRecord`：全局连续序号 `seq`（从 1 开始）+ 写入方栅栏世代
  `fence`（初始 1）。复用已有映射、`advance`、被丢弃的包、失败的批量
  分配都**不**产生记录；过期也不进日志（见设计取舍）。
- **备用重放**：`AddressDependentNAT.standby(config)` 创建备用实例
  （只读，本地写入抛 `RoleError`）。`apply_record` 严格按 `seq` 逐条
  应用：重复记录（序号已应用且内容完全一致）幂等返回
  `ApplyOutcome.DUPLICATE`；缺口抛 `JournalGapError`；同序号内容不同
  或与当前状态冲突抛 `JournalConflictError`；记录栅栏低于当前栅栏
  （旧主写入）抛 `StaleFenceError`。所有拒绝都发生在任何状态变更之前。
- **栅栏接管**：`promote(through_seq, new_fence=...)` 仅允许备用在
  **已追平指定序号**（`last_seq >= through_seq`，否则
  `NotCaughtUpError`）且 `new_fence` **严格大于**当前栅栏（缺省 +1）
  时生效。接管后日志、`seq` 与映射 `generation` 计数全部保留并连续；
  旧主继续产生的记录携带旧栅栏，被已接管实例拒绝（`StaleFenceError`）。
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
    JournalKind, JournalRecord, ApplyOutcome,
    NATError, ValidationError, PortExhaustionError,
    SearchBudgetExhaustedError,
    ReplicationError, RoleError, JournalGapError,
    JournalConflictError, StaleFenceError, NotCaughtUpError,
)

nat = AddressDependentNAT(NATConfig(
    public_ip="203.0.113.7",
    external_ports=(6100, 6101, 6102),
    lifetime=300,        # 映射空闲存活（整数时间单位），>= 1
    quarantine=60,       # 端口释放后隔离时长 Q，>= 0
    search_budget=None,  # 单次分配最多检查的端口数；None = 池大小（全池扫描）
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

# 复制与接管
AddressDependentNAT.standby(config) -> AddressDependentNAT  # 备用实例（只读）
nat.role -> str                          # "primary" | "standby"
nat.fence -> int                         # 当前栅栏世代（初始 1）
nat.last_seq -> int                      # 已写/已应用的最大记录序号（0 = 空）
nat.journal() -> tuple[JournalRecord, ...]        # 有序记录快照（seq 升序）
nat.apply_record(record: JournalRecord) -> ApplyOutcome     # APPLIED / DUPLICATE
nat.promote(through_seq: int, new_fence: int | None = None) -> None
```

`TranslationResult.accepted=True` 时 `rewritten` 为改写后的 `FiveTuple`
（UDP，protocol=17）；否则 `reason` 为 `DropReason` 之一：
`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` / `DEST_MISMATCH`。

## 错误语义

所有异常继承 `NATError`：

| 异常 | 含义 | 状态影响 |
|---|---|---|
| `ValidationError` | 非法输入（类型/取值/越界/时钟回退/批内重复 key 等） | 在任何变更之前抛出，状态不变 |
| `PortExhaustionError` | 全池扫描后容量不足（证明无解），带 `needed/available/pool_size` | 整体回滚，状态不变 |
| `SearchBudgetExhaustedError` | 搜索预算耗尽（未证明无解），带 `budget/inspected/needed/found` | 整体回滚，状态不变 |
| `RoleError` | 备用实例本地写入 / 对主实例调用 `promote` | 状态不变 |
| `JournalGapError` | 记录序号缺口（必须按序应用），带 `expected/got` | 状态不变 |
| `JournalConflictError` | 同序号内容不同，或记录与当前状态冲突（未知映射、端口占用/隔离、时钟回退等） | 状态不变 |
| `StaleFenceError` | 记录来自旧栅栏世代（旧主写入），带 `seq/record_fence/current_fence` | 状态不变 |
| `NotCaughtUpError` | 备用未追平指定序号即请求接管，带 `through_seq/applied_seq` | 状态不变 |

后五种均继承 `ReplicationError`（本身继承 `NATError`）。

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
| 记录 `seq` / `fence` / `through_seq` / `new_fence` | 1..2^63-1（`through_seq` 允许 0），`new_fence` 必须严格大于当前栅栏 |

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
- **过期不进日志**：映射过期是 `(expires_at, 时钟)` 的纯函数，备用在
  记录携带的 `at` 时刻做同样的 housekeeping 即可与主逐状态收敛，无需
  过期记录。这也是隔离起点定为 `expires_at`（逻辑死亡时刻）的原因：
  若按 housekeeping 发现时刻计，主备发现时机不同会导致隔离状态分叉。
- **记录携带结果值**：CREATE/REFRESH 记录直接携带 `expires_at` 等结果
  字段，重放不重新推导；但 CREATE 端口必须在配置池内且未被占用/隔离，
  否则判 `JournalConflictError`（主备配置应一致，库不额外校验配置相等）。
- **接管不重置计数**：`promote` 保留日志、`seq` 与映射 `generation`
  计数，接管后分配自然延续；栅栏世代是唯一单调递增的信任边界，
  旧主的记录因栅栏过旧而被拒绝。
- **参考实现独立**：`tests/reference_nat.py` 只用字典/元组重写同一契约，
  不导入被测核心；差分测试逐操作比对公开结果与规范化状态签名。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，不含
  端口依赖/锥形 NAT、hairpin、ALG、分片、ICMP 等行为。
- 单实例、单线程；状态只在内存中，无持久化。
- 端口分配为"最小空闲"策略的线性扫描，复杂度 O(池大小)；
  本题上限（65535）下足够。
- 出站方向无映射时**丢弃**而非隐式建映射（建映射必须显式 `allocate`）。
- 时钟接近 `MAX_TIME` 时（`now + lifetime` 溢出）抛 `ValidationError`。
- 复制为单备用、单方向：无多副本、无反熵/快照传输；journal 全量驻留
  内存且只增不减，每个成功改写的包都产生一条 REFRESH 记录。
- 备用只有 `promote` 后才能本地写入；旧主实例自身无法感知已被取代，
  其写入在记录流入已接管实例时被拒绝（`StaleFenceError`）。
- 不实现备用落后时的无损接管与端口世代回收（题面范围外）：
  `promote` 只校验已追平指定序号。

## 目录

```
adnat/            本题库（可导入）
  __init__.py     公开导出
  model.py        冻结数据结构 + NATConfig + JournalRecord
  errors.py       异常层级（含 ReplicationError 子树）
  core.py         AddressDependentNAT 核心（含 journal/apply/promote）
  _validate.py    输入校验原语
tests/
  test_contract.py      契约测试（手工期望值）
  test_differential.py  差分测试（核心 vs 独立字典参考）
  test_replication.py   复制与接管测试（手工期望值 + 重放一致性核对）
  reference_nat.py      独立字典参考实现（测试 oracle）
demo.py           固定输入演示（含复制与接管）
```
