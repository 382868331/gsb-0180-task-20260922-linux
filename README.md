# adnat —— 多租户地址依赖 NAT 端点生命周期（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟**多租户**地址依赖（address-dependent）
映射与过滤的 UDP NAT。**纯状态库，不发任何网络包**；核心、测试、演示全部
离线。多个客户可以使用完全相同的内网 IP 与端口而互不撞映射。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

```bash
./.venv/bin/python -m unittest discover -s tests -v   # 全部测试（契约 + 差分）
./.venv/bin/python demo.py                            # 两租户 + 一次真实跨租户批量失败
```

两条命令均在秒级完成（实测测试约 0.3 秒、demo 约 0.05 秒，远低于 90 秒）；
隔离虚拟环境已在仓库内备好，仅用标准库，无需安装任何依赖、不访问网络。

## 租户模型

- 映射身份 = **(租户 ID, 租户内四元组 key)**。key 仍为
  `(内网IP, 内网端口, 目的IP, 目的端口)`。两个租户的 key 可以完全相同，
  它们是互不相干的两条映射。
- 每个租户在 `NATConfig.tenants` 中显式配置：**非空字符串 ID**、自己的
  **外端口子集**、**最大活跃映射数**（有限配额）。
  - 子集两两**不重叠**，且只能取自 `NATConfig.external_ports` 总池
    （总池允许存在未分配给任何租户的剩余端口）。
  - ID 重复、子集重叠、端口越界、配额非法等——构造 `NATConfig` 时
    **整体拒绝**（抛 `ValidationError`），不存在部分生效。
  - 租户表构造后**固定**，不支持在线迁移。
- **旧接口兼容**：不传 `tenants` 时自动生成唯一的隐式租户 `"default"`
  （独占总池、无配额）。不使用任何新参数时，行为与单租户基线完全一致。
- **入站由外端口反查租户**：端口全局唯一属主（子池互不重叠），
  `TranslationResult.tenant` 带回收发身份；出站沿用调用指定的租户。
- **作用域**：查询（`get_mapping` / `snapshot_mappings`）、`release`、
  `translate_outbound` 都必须明确租户，绝不会仅凭相同内网端点作用到
  另一家；未知租户一律 `ValidationError`。
- **配额语义**：复用已有活跃映射不额外占配额；过期与 `release` 立即解除
  活跃配额，但端口隔离期 Q 不能跳过——因此可能出现"配额有空、
  端口不可用"的 `PortExhaustionError`。配额不足单独报
  `QuotaExceededError`，绝不伪装成端口耗尽。

## 时间与端口契约（与基线一致）

- **显式整数时钟**：`advance_tenants(seconds)` 推进；每次公开调用先按当前
  时钟做 housekeeping（过期回收、隔离到期释放）再处理请求。时钟只增不减。
  映射在 `now >= expires_at` 时过期（**边界即死**）；成功改写的包刷新
  `expires_at = now + lifetime`。
- **隔离 Q**：映射过期或被 `release` 后，端口隔离 `quarantine` 个时间单位，
  `now >= released_at + Q` 才可复用。
- **外端口**：从该租户子池中选**最小空闲**端口（子池升序去重）。
- **入站过滤**：必须命中映射外端口、源端点 == 映射对端、目的 IP == 公网 IP。
- **generation**：每条映射创建时取**全局**单调递增序号（跨租户共享一个
  序号，从 1 开始）。包携带值不一致（且非 0）即判迟到包丢弃
  （`STALE_GENERATION`）；`generation=0` 不参与校验。

## 分配的原子性与固定检查顺序

`allocate_many`（单租户批量）与 `allocate_across_tenants`（跨租户批量）
都是**全部满足才提交**；任一步失败，状态（含时钟、generation 序号）与
调用前完全一致。固定顺序：

1. **完整输入校验**：类型、租户存在、批内 `(租户, key)` 不重复、时钟、溢出；
2. **在候选时刻规划过期回收**（纯函数，不改状态）；
3. **配额检查**（逐租户，全部先于端口规划）：不足抛 `QuotaExceededError`；
4. **按输入次序（租户首次出现次序）分配端口**：预算逐租户独立计数——
   预算耗尽抛 `SearchBudgetExhaustedError`（未证明无解）；全子池不够抛
   `PortExhaustionError`（证明无解）；
5. **一次性提交**：housekeeping + 按输入次序建映射、发 generation。

## 公开接口

```python
from adnat import (
    AddressDependentNAT, NATConfig, TenantConfig, TenantRequest,
    Endpoint, Packet, AllocationRequest, AllocationResult,
    TranslationResult, Mapping, FiveTuple, DropReason, DEFAULT_TENANT,
    NATError, ValidationError, QuotaExceededError,
    PortExhaustionError, SearchBudgetExhaustedError,
)

cfg = NATConfig(
    public_ip="203.0.113.7",
    external_ports=(6001, 6002, 6003, 6101, 6102, 6103),
    lifetime=300, quarantine=60, search_budget=None,
    tenants=(                                  # 省略 = 隐式单 default 租户
        TenantConfig("cust-alpha", (6001, 6002, 6003), max_mappings=100),
        TenantConfig("cust-beta",  (6101, 6102, 6103), max_mappings=100),
    ),
)
nat = AddressDependentNAT(cfg)

# 单租户分配（旧接口 tenant_id 默认 DEFAULT_TENANT）
nat.allocate(internal, remote, *, tenant_id="cust-alpha", at=None) -> AllocationResult
nat.allocate_many(requests, *, tenant_id=..., at=None) -> list[AllocationResult]

# 跨租户原子批量：每项显式携带租户；全成功或整体回滚
nat.allocate_across_tenants(
    [TenantRequest("cust-alpha", internal, remote),
     TenantRequest("cust-beta",  internal2, remote2)], at=None,
) -> list[AllocationResult]

# 包改写
nat.translate_outbound(packet, *, tenant_id=..., at=None) -> TranslationResult
nat.translate_inbound(packet, *, at=None)  -> TranslationResult  # 租户由外端口反查

# 生命周期 / 查询（全部显式租户作用域）
nat.release(key, *, tenant_id=..., at=None) -> bool
nat.get_mapping(key, *, tenant_id=...) -> Mapping | None
nat.snapshot_mappings(*, tenant_id=None) -> list[Mapping]       # None=全部租户
nat.quarantined_ports(*, tenant_id=None) -> dict[int, int]
nat.stats(*, tenant_id=None) -> dict[str, int]

# 时钟
nat.advance_tenants(seconds) -> list[(tenant_id, key)]          # 任何配置可用
nat.advance(seconds) -> list[key]            # 仅隐式 default 单租户（旧接口）
nat.now -> int
```

`AllocationResult` 含 `tenant / key / mapping / created`；`Mapping` 含
`tenant` 与其余基线字段。`TranslationResult.accepted=True` 时 `rewritten`
为 `FiveTuple`（UDP，protocol=17）且 `tenant` 为命中租户；否则 `reason`
为 `DropReason`：`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` /
`DEST_MISMATCH` / `UNKNOWN_TENANT`（外端口不属于任何租户子池）。

## 错误语义

所有异常继承 `NATError`：

| 异常 | 含义 | 状态影响 |
|---|---|---|
| `ValidationError` | 非法输入（类型/取值/越界/时钟回退/未知租户/批内身份重复/租户表非法等） | 在任何变更之前抛出，状态不变 |
| `QuotaExceededError` | 租户活跃配额不足（带 `tenant_id/active/new/limit`），与端口容量无关 | 整体回滚，状态不变 |
| `PortExhaustionError` | 全（子）池扫描后端口不足（带 `needed/available/pool_size/tenant`） | 整体回滚，状态不变 |
| `SearchBudgetExhaustedError` | 预算耗尽，未证明无解（带 `budget/inspected/needed/found/tenant`） | 整体回滚，状态不变 |

输入校验规则（全库统一）：整数参数只接受精确 `int`；**`bool` 一律拒绝**；
`float`（含 `3.0`）一律拒绝，因此 **NaN/Infinity 在类型层即被拒绝**；
IPv4 只接受规范点分十进制（无前导零）；租户 ID 只接受非空 `str`。
不做任何静默纠正。

## 输入上限

| 参数 | 上限 |
|---|---|
| 端口 | 1..65535 |
| 总端口池大小 | 1..65535（`MAX_POOL_SIZE`），无重复；租户子集为其互不重叠的非空划分（允许有剩余） |
| 租户 `max_mappings` | 1..65535（显式租户必须给有限值） |
| 单批分配请求数 | `MAX_BATCH_REQUESTS` = 65535，且批内 `(租户, key)` 不重复 |
| 时间类整数 | 0..2^63-1（`MAX_TIME`），且 `now + lifetime` 不得溢出 |
| `generation` | 0..2^63-1 |

## 精度说明（误差口径）

本库**不产生浮点结果**：端口选择、过期判定、隔离判定、配额计数、
generation 比较全部为精确整数运算，严格不等式
（`now >= expires_at` 过期、`now >= released_at + Q` 解除隔离），
边界行为由 `tests/test_contract.py`、`tests/test_tenants.py` 中的边界
用例逐点固定，无容差。

## 设计取舍

- **纯函数规划 + 一次性提交**：批量分配把"校验/过期规划/配额/端口规划"
  与"状态提交"分开，从结构上保证失败即零副作用（不发 generation、
  不推进时钟），而非事后补偿回滚。
- **配额检查整体先于端口规划**：保证"配额不足"有确定、单一的报错，
  不会因规划顺序把配额问题报成端口耗尽。
- **预算逐租户独立**：跨租户批量中每家只在自己的子池内扫描，预算各自
  计数；与基线"预算按实际检查端口计数"的口径一致。
- **入站不接受租户参数**：租户身份只能由外端口反查，避免调用方伪造
  作用域；外端口无属主时区分 `NO_MAPPING`（端口属于某子池但无映射）
  与 `UNKNOWN_TENANT`（端口不属于任何子池）。
- **`advance` 与 `advance_tenants` 并存**：旧配置下 `advance` 返回租户内
  key（基线形状）；显式租户表下相同四元组可能同时过期，`advance` 有歧义，
  故拒绝并要求使用带租户身份的 `advance_tenants`。
- **复用不刷新**：`allocate` 命中已有映射只复用、不刷新过期时间、不占
  配额；只有成功的包改写刷新（模拟真实流量保活）。
- **参考实现独立**：`tests/reference_nat.py` 只用字典/元组重写同一契约
  （含多租户与跨租户批量），不导入被测核心；差分测试逐事件比对公开
  结果、丢弃原因、租户身份与规范化状态签名（含全局 generation 序号）。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，不含
  端口依赖/锥形 NAT、hairpin、ALG、分片、ICMP 等行为。
- 租户表构造后固定；无在线增删租户 / 端口子集迁移。
- 单实例、单线程；状态只在内存中，无持久化。
- 端口分配为各子池"最小空闲"线性扫描，O(子池大小)；本题上限下足够。
- 出站方向无映射时**丢弃**而非隐式建映射（建映射必须显式 `allocate`）。
- 时钟接近 `MAX_TIME` 时（`now + lifetime` 溢出）抛 `ValidationError`。

## 目录

```
adnat/            本题库（可导入）
  __init__.py     公开导出
  model.py        冻结数据结构 + NATConfig / TenantConfig
  errors.py       异常层级（含 QuotaExceededError）
  core.py         多租户 AddressDependentNAT 核心
  _validate.py    输入校验原语
tests/
  test_contract.py           基线契约测试（手工期望值）
  test_tenants.py            多租户契约测试（隔离/配额/回滚/边界/旧接口）
  test_differential.py       基线差分测试（核心 vs 独立字典参考）
  test_tenant_differential.py 多租户差分随机游走（含跨租户批量失败）
  reference_nat.py           独立字典参考实现（测试 oracle，含多租户）
demo.py           固定输入演示：两租户 + 一次真实跨租户批量失败
```
