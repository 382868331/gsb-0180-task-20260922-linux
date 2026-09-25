# adnat —— 地址依赖 NAT 端点生命周期（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟地址依赖（address-dependent）映射与
过滤的 UDP NAT。**纯状态库，不发任何网络包**；核心、测试、演示全部离线。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

固定环境为仓库内 `./.venv`（Linux 原生 Python 3.14.7，仅标准库）：

```bash
./.venv/bin/python -m unittest discover -s tests -v   # 契约 + 差分 + hairpin
./.venv/bin/python demo.py                            # 固定输入演示，秒级完成
```

无需 Docker、数据库服务或在线 API；不发任何网络包，所有地址均为
TEST-NET 合成地址（`198.51.100.0/24`、`203.0.113.0/24`、`10.0.0.0/8`）。

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
  单位，`now >= released_at + Q` 才可复用。
- **generation**：每条映射创建时取全局单调递增序号（从 1 开始）。合成包
  可携带 `generation`；与映射当前值不一致即判**迟到包**丢弃
  （`STALE_GENERATION`）。`generation=0` 表示不参与校验。
- **批量原子性**：`allocate_many` 先完成全部校验与容量规划（纯函数），
  全部可满足才一次性提交；失败时**状态与调用前完全一致**（含时钟不动）。
- **预算与无解分开**：容量检查按端口升序进行，最多检查 `search_budget`
  个端口。预算耗尽抛 `SearchBudgetExhaustedError`（未扫描全池，**不**
  代表无解）；全池扫描仍不够抛 `PortExhaustionError`（**证明无解**）。
- **Hairpin（内网折返）**：`translate_hairpin` 是独立新入口。内网源访问
  `(公网IP, 某条仍有效映射的外端口)` 时：
  - 目的映射必须**属于当前公网地址且未过期**（外端口命中），其内网
    端点成为新目的；源按**原出站规则**取得映射
    key=`(源IP, 源端口, 公网IP, 外端口)`，已存在则复用、否则从端口池
    新建。成功五元组为 `(公网IP, 源外端口) -> 目的映射.内网端点`，
    结果携带源、目的双方映射快照（含双方 generation）。
  - 这是入站"源必须等于记录对端"过滤的**唯一明确例外，且只在该入口
    生效**；`translate_inbound` 的普通入站过滤不被放宽。
  - **一次提交**：目的查找、源端口规划与双方超时刷新合成一次提交；
    源端口池耗尽 / 搜索预算耗尽在任何计时更新之前抛出，目的映射的
    `last_seen/expires_at` 不变化。自己访问自己的映射允许，但容量只
    扣源这一份（复用不再扣）。
  - generation 只校验**目的映射**（`0` 照旧豁免）；源映射的
    generation 随结果返回而不要求与包号相等——源、目的是不同映射，
    全局单调计数使两者 generation 必然不同。

## 公开接口

```python
from adnat import (
    AddressDependentNAT, NATConfig, Endpoint, Packet,
    AllocationRequest, AllocationResult, TranslationResult,
    HairpinResult,
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
))

nat.allocate(internal: Endpoint, remote: Endpoint, *, at: int | None = None)
    -> AllocationResult
nat.allocate_many(requests: list[AllocationRequest], *, at: int | None = None)
    -> list[AllocationResult]            # 原子：全成功或整体回滚
nat.translate_outbound(packet: Packet, *, at: int | None = None)
    -> TranslationResult                 # 不隐式建映射；无映射丢弃
nat.translate_inbound(packet: Packet, *, at: int | None = None)
    -> TranslationResult
nat.translate_hairpin(packet: Packet, *, at: int | None = None)
    -> HairpinResult                     # 内网折返；入站对端过滤的唯一例外
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
`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` / `DEST_MISMATCH`。

`HairpinResult` 字段：`accepted`、`rewritten`、`reason`、
`source_mapping`（源按出站规则取得/复用的映射）、
`destination_mapping`（被外端口命中的目的映射）、`source_created`
（源映射本次是否新建）。双方 generation 直接读两个映射快照即可。

### Hairpin 示例（手工五元组）

```python
PUB = "203.0.113.7"
a    = Endpoint("10.0.0.8", 4000)      # 目的映射拥有者
b    = Endpoint("10.0.0.9", 5000)      # 内网访问者
peer = Endpoint("198.51.100.10", 53)

nat = AddressDependentNAT(NATConfig(
    public_ip=PUB, external_ports=(6001, 6002, 6003)))
nat.allocate(a, peer)                  # a 的映射：外端口 6001, gen 1

# b 访问 a 的公网端点；目的折回 a，源取得新外端口 6002（gen 2）
res = nat.translate_hairpin(Packet(src=b, dst=Endpoint(PUB, 6001), gen=1))
# res.rewritten: (17, 203.0.113.7, 6002, 10.0.0.8, 4000)
# res.source_mapping.generation      == 2
# res.destination_mapping.generation == 1
# 再次同包 -> source_created=False（复用，不重复扣容量）

# 普通入站入口不享受该例外：b 直接打进 translate_inbound 仍是 PEER_MISMATCH
nat.translate_inbound(Packet(src=b, dst=Endpoint(PUB, 6001)))
# -> accepted=False, reason=PEER_MISMATCH
```

## 错误语义

所有异常继承 `NATError`：

| 异常 | 含义 | 状态影响 |
|---|---|---|
| `ValidationError` | 非法输入（类型/取值/越界/时钟回退/批内重复 key 等） | 在任何变更之前抛出，状态不变 |
| `PortExhaustionError` | 全池扫描后容量不足（证明无解），带 `needed/available/pool_size`；`allocate_many` 与 `translate_hairpin` 的源分配均适用 | 整体回滚，状态不变 |
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
- **Hairpin 是显式独立入口而非隐式放宽**：内网折返与普通入站共用目的
  映射查找，但对端过滤例外只写在 `translate_hairpin` 内，
  `translate_inbound` 一行未改；调用方必须显式选择折返语义，无法经由
  普通入站路径绕过地址依赖过滤。
- **Hairpin 的规划/提交分段**：与 `allocate_many` 同一手法——先
  housekeeping、目的查找、generation 校验、`_plan_ports` 纯函数规划，
  全部成立才一次性建源映射并刷新双方计时；端口耗尽在刷新之前抛出，
  因此目的映射计时在失败路径上可证明不变（测试逐点固定）。
- **参考实现独立**：`tests/reference_nat.py` 只用字典/元组重写同一契约，
  不导入被测核心；差分测试逐操作比对公开结果与规范化状态签名。
  Hairpin 契约由 `tests/test_hairpin.py` 的手工五元组期望值固定。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，含一个
  显式 hairpin 入口；不含端口依赖/锥形 NAT、ALG、分片、ICMP 等行为。
- Hairpin 只做单包的 NAT 层折返改写（目的折回内网端点、源按出站规则
  映射），不模拟回包路径学习、连接跟踪会话合并或路由二次查表。
- 单实例、单线程；状态只在内存中，无持久化；不含租户隔离或主备复制。
- 端口分配为"最小空闲"策略的线性扫描，复杂度 O(池大小)；
  本题上限（65535）下足够。
- 出站方向无映射时**丢弃**而非隐式建映射（建映射必须显式 `allocate`）。
- 时钟接近 `MAX_TIME` 时（`now + lifetime` 溢出）抛 `ValidationError`。

## 目录

```
adnat/            本题库（可导入）
  __init__.py     公开导出
  model.py        冻结数据结构 + NATConfig（含 HairpinResult）
  errors.py       异常层级
  core.py         AddressDependentNAT 核心（含 translate_hairpin）
  _validate.py    输入校验原语
tests/
  test_contract.py      契约测试（手工期望值）
  test_differential.py  差分测试（核心 vs 独立字典参考）
  test_hairpin.py       Hairpin 契约测试（手工五元组，两方向）
  reference_nat.py      独立字典参考实现（测试 oracle）
demo.py           固定输入演示（含 hairpin 去/回程与边界）
```
