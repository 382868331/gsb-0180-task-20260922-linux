# adnat —— 地址依赖 NAT 端点生命周期（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟地址依赖（address-dependent）映射与
过滤的 UDP NAT。**纯状态库，不发任何网络包**；核心、测试、演示全部离线。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

```bash
python3.14 -m venv .venv                  # 可选：创建虚拟环境
source .venv/bin/activate                 # 激活后 python 即 3.14.7
python -m unittest discover -s tests -v   # 全部测试（契约 + 差分 + 差错入口）
python demo.py                            # 首轮：地址依赖映射固定输入演示
python demo_iteration.py                  # 本轮：差错报文反向定位演示
```

无需安装任何第三方包（`requirements.txt` 为空占位）；全部入口离线、
不使用 Docker/外部服务/真实凭据，两个演示均在 1 秒内真实算出结果
（无 sleep、无预录输出，远低于 90 秒上限）。

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

## 公开接口

```python
from adnat import (
    AddressDependentNAT, NATConfig, Endpoint, Packet,
    AllocationRequest, AllocationResult, TranslationResult,
    ErrorPacket, ErrorTranslationResult, Mapping, FiveTuple, DropReason,
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
nat.translate_error(packet: ErrorPacket, *, at: int | None = None)
    -> ErrorTranslationResult             # 差错报文反向定位；只读，不改寿命
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
`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` / `DEST_MISMATCH`；
差错报文入口额外可能给出 `QUOTE_NOT_UDP` / `QUOTE_MALFORMED`。

## 差错报文入口（本轮新增）

`translate_error` 是一个**合成的差错报文入口**（ICMP 风格，外层
protocol=1）。它**不是**完整网络协议栈、不真实发包，只解析题面明确
给出的最小结构 `ErrorPacket`：

| 字段 | 含义 |
|---|---|
| `outer_src` | 差错报文发送方端点（地址依赖过滤要求其 == 映射对端） |
| `outer_dst` | 外层目的，必须等于本机公网端点（固定公网 IP + 外端口） |
| `quoted_src` | 被引用原 UDP 包的源端点，必须 == `outer_dst`（NAT 重写后的公网端点） |
| `quoted_dst` | 被引用原 UDP 包的目的端点，必须 == 映射记录的对端 |
| `quoted_protocol` | 引用协议，必须为 UDP=17 |
| `generation` | 创建映射时返回的世代标记；`0` = 未携带 |

匹配按以下顺序进行，任一不满足即丢弃（结构完整的语义问题不抛异常）：

1. `outer_dst.ip == public_ip`，否则 `DEST_MISMATCH`；
2. `quoted_protocol == 17`，否则 `QUOTE_NOT_UDP`；
3. `quoted_src == outer_dst`（同一公网端点），否则 `QUOTE_MALFORMED`；
4. 外端口当前必须仍有有效映射，否则：携带的 `generation` 曾占用过
   该端口 -> `STALE_GENERATION`（端口复用前的旧引用）；否则 `NO_MAPPING`；
5. 引用远端与外层源都必须等于该映射记录的对端（地址依赖），否则
   `PEER_MISMATCH`（携带的 `generation` 能证明是旧连接时仍判
   `STALE_GENERATION`）；
6. `generation != 0` 时必须等于映射当前世代标记，否则 `STALE_GENERATION`。

命中后返回 `ErrorTranslationResult`：

- `outer_target`：改写后的外层目标五元组（protocol=1 ICMP，源=差错发送方，
  目的=找回的内部端点）；
- `quoted`：原样回显的被引用 UDP 五元组（protocol=17）；
- `mapping_id`：采用映射的 ID，即创建映射时返回的
  `AllocationResult.mapping.generation`（全局唯一、单调递增，从 1 开始）。

**语义不变量**：差错报文**不创建新映射、不刷新 `last_seen`/`expires_at`、
不改变端口占用/隔离**；重复差错返回完全一致的结果。正常 UDP 回包
（`translate_inbound` 成功）才按既有规则延长寿命。

**世代标记的能力边界**：`generation` 是创建映射时返回的不透明标记，
专门用于排除端口复用后的旧引用。仅有现实五元组（`generation=0`）时，
若端口已被**完全相同的五元组**复用，本库**不承诺**识别该旧引用——
这是题面明确接受的已知限制，不做猜测性判断。

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
- **参考实现独立**：`tests/reference_nat.py` 只用字典/元组重写同一契约，
  不导入被测核心；差分测试逐操作比对公开结果与规范化状态签名。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，不含
  端口依赖/锥形 NAT、hairpin、ALG、分片等行为。差错报文入口只处理
  题面给出的合成结构（外层 ICMP 风格 protocol=1 + 引用 UDP 五元组），
  不是完整 ICMP/网络协议栈，不解析真实报文字节、不真实发包。
- 差错报文仅按“公网端点 + 对端 + 协议 + 世代标记”反向定位；不携带
  `generation`（=0）时，无法排除**完全相同五元组**的端口复用旧引用。
- 差错报文不改变任何状态（不建映射、不延寿、不动端口隔离）。
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
  test_error_entry.py   差错报文入口契约 + 独立字典对照
  reference_nat.py      独立字典参考实现（测试 oracle，含 error 对照）
demo.py             首轮固定输入演示
demo_iteration.py   本轮差错报文入口演示（90 秒内，无 sleep）
```
