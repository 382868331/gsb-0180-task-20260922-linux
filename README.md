# adnat —— 端口池按租户隔离的地址依赖 NAT 端点生命周期（合成 UDP 状态库）

离线网络中间层工程的可复用模块：模拟地址依赖（address-dependent）映射与
过滤的 UDP NAT，并在**同一个离线 NAT 模型**里支持多个客户（租户）——它们
可以使用完全相同的内网 IP 与端口，但映射与外端口互不碰撞。**纯状态库，
不发任何网络包**；核心、测试、演示全部离线。

- Python 版本：**3.14.7**（仅标准库，语法兼容 3.10+；无需安装任何额外依赖）
- 平台：Linux 原生
- 不宣称兼容任何 RFC/行业标准；仅按本 README 固定的契约实现一个有限子集。

## 运行

```bash
./.venv/bin/python -m unittest discover -s tests -v   # 全部测试（契约 + 两组差分）
./.venv/bin/python demo.py                            # 固定输入演示，秒级完成
```

演示在 90 秒内跑完：两个租户使用同一内网地址的隔离映射、一次成功的跨租户
批量，以及**一次真实发生的跨租户批量失败**（配额不足）与整批回滚验证。

## 模型与契约

### 单租户基线（不传租户配置时完全保持）

- **出站 key** = `(内网IP, 内网端口, 目的IP, 目的端口)`。同一内网端点访问
  不同目的产生**不同映射**（地址依赖）。公网 IP 固定（`NATConfig.public_ip`）。
- **外端口**：从给定有限池 `external_ports` 中选**最小空闲**端口
  （池可乱序给出，内部升序去重）。
- **入站过滤**：包必须命中某映射的外端口，且源端点 == 该映射记录的对端，
  目的 IP == 公网 IP，否则丢弃。
- **时间**：显式整数时钟。`advance(seconds)` 推进；每次公开调用先按候选
  时刻做 housekeeping（过期回收、隔离到期释放）再处理请求。时钟只增不减。
  映射在 `now >= expires_at` 时过期（**边界即死**）；成功改写的包刷新
  `expires_at = now + lifetime`。
- **隔离 Q**：映射过期或被 `release` 后，其端口隔离 `quarantine` 个时间
  单位，`now >= released_at + Q` 才可复用（隔离时间戳记在**实际回收时刻**）。
- **generation**：每条映射创建时取全局单调递增序号（从 1 开始，跨租户
  共享一个序号）。合成包可携带 `generation`；与映射当前值不一致即判
  **迟到包**丢弃（`STALE_GENERATION`）。`generation=0` 表示不参与校验。
- **批量原子性**：分配先完成全部校验与规划（纯函数），全部可满足才一次性
  提交；失败时**状态与调用前完全一致**（含时钟不动、generation 不增长）。
- **预算与无解分开**：端口检查按升序进行，最多检查 `search_budget` 个端口。
  预算耗尽抛 `SearchBudgetExhaustedError`（未扫完，**不**代表无解）；全池
  扫描仍不够抛 `PortExhaustionError`（**证明无解**）。

### 多租户扩展（显式租户配置）

`NATConfig(tenants=(TenantConfig(...), ...))` 给出租户表后：

- **租户身份进入映射身份**：完整身份为
  `(tenant_id, 内网IP, 内网端口, 目的IP, 目的端口)`。两个租户的内网四元组
  即使逐字节相同，也是互不可见的两条映射，端口也不会相撞。租户内仍按原
  五元组规则识别身份、按最小可用端口分配。
- **独占外端口子集**：每租户配置自己的 `external_ports` 子集；子集之间
  **互不重叠**，合起来**只能取自**总池（不要求覆盖总池，未分配端口不属
  任何租户）。配置出现**重复 ID、子集重叠、端口越界**时，`NATConfig`
  **整体拒绝**（`ValidationError`）。租户表构造后固定，本次不做在线迁移。
- **每租户活跃配额**：`max_active_mappings` 限制候选时刻回收过期映射后的
  活跃映射数。**复用已有映射不额外占配额**；过期与 `release` 解除活跃配额；
  但**端口隔离期不能跳过**——配额已空、端口仍隔离时，失败原因是
  `PortExhaustionError` 而不是配额错误。
- **配额不足单独报错**：`QuotaExceededError`，与端口容量严格分开，绝不
  伪装成端口耗尽。
- **入站反解租户**：入站包按外端口定位映射（子集不重叠 ⇒ 端口唯一反解
  租户），`TranslationResult.tenant` 带回租户身份；定位到映射后因代数/对端
  不符丢弃时也带回租户；连映射都没定位到（`NO_MAPPING`/`DEST_MISMATCH`）
  时为 `None`。
- **查询 / 释放 / 出站必须显式指定租户**：不允许仅凭相同内网端点触及另一
  家。多租户模式下省略 `tenant` 直接报 `ValidationError`，不会落入隐含租户。
- **跨租户原子批量** `allocate_across_tenants`：全部满足才提交。其中一个
  租户超配额、端口不够或共享搜索预算耗尽，其他租户也不留下新映射、序号不
  增长、时间不推进。检查顺序固定：

  1. **完整输入校验**（类型、批大小、租户均存在、批内 `(tenant,key)` 不
     重复、时钟单调、时间溢出）；
  2. **在候选时刻规划过期回收**（纯函数，不改状态；据此计算活跃集合与隔离
     投影）；
  3. **配额检查**（租户按 ID 升序报告，错误确定）；
  4. **按输入次序分配端口**（租户按其首次出现次序，租户内按输入次序取最小
     可用端口）；搜索预算按基线口径对**实际检查过的端口**计数，在所有租户
     子集间共享；
  5. 全部成功才一次性提交。

> 边界澄清（相对基线的一处收紧）：当某次调用用 `at=` 直接跨过映射过期点、
> 且尚未发生过任何 housekeeping 时，基线纯函数规划会把"即将在本次提交中
> 过期回收"的端口当作空闲，导致同一端口在新映射占用的同时残留一条隔离
> 记录。本实现的规划阶段按"提交 housekeeping 后"的投影计算隔离集合
> （Q>0 时刚过期端口本次不可用，Q=0 时立即可用），隔离期因此不可能被跳过。
> 两组差分测试的独立字典参考同步按此口径实现；基线先 `advance` 再分配的
> 常规路径行为不变。

## 公开接口

```python
from adnat import (
    AddressDependentNAT, NATConfig, TenantConfig,
    TenantAllocationRequest, Endpoint, Packet,
    AllocationRequest, AllocationResult, TranslationResult,
    Mapping, FiveTuple, DropReason,
    NATError, ValidationError, PortExhaustionError,
    SearchBudgetExhaustedError, QuotaExceededError,
)

# ---- 配置 ----
NATConfig(
    public_ip="203.0.113.7",
    external_ports=(6100, 6101, 6102, 6103, 6104),
    lifetime=300,        # 映射空闲存活（整数时间单位），>= 1
    quarantine=60,       # 端口释放后隔离时长 Q，>= 0
    search_budget=None,  # 每次分配调用最多检查的端口数；None = 总池大小
    tenants=(            # None（默认）= 单租户基线模式
        TenantConfig(tenant_id="alpha",
                     external_ports=(6100, 6101, 6102),
                     max_active_mappings=100),
        TenantConfig(tenant_id="beta",
                     external_ports=(6103, 6104),
                     max_active_mappings=50),
    ),
)

# ---- 单租户批量（tenant=None 仅限未配置租户表的基线模式）----
nat.allocate(internal, remote, *, at=None, tenant="alpha") -> AllocationResult
nat.allocate_many([AllocationRequest(internal, remote), ...], *, at=None,
                  tenant="alpha") -> list[AllocationResult]   # 原子

# ---- 跨租户批量（原子；全部满足才提交）----
nat.allocate_across_tenants(
    [TenantAllocationRequest("alpha", internal_a, remote_a),
     TenantAllocationRequest("beta",  internal_b, remote_b)],
    *, at=None) -> list[AllocationResult]

# ---- 包改写 ----
nat.translate_outbound(packet, *, at=None, tenant="alpha") -> TranslationResult
nat.translate_inbound(packet, *, at=None)                   # 租户由外端口反解
    -> TranslationResult

# ---- 生命周期 / 查询（均须显式租户）----
nat.release(key, *, at=None, tenant="alpha") -> bool        # 不存在返回 False
nat.advance(seconds) -> list                                # 见下
nat.get_mapping(key, *, tenant="alpha") -> Mapping | None
nat.snapshot_mappings(*, tenant=None) -> list[Mapping]      # None=全部租户
nat.quarantined_ports() -> dict[int, int]
nat.stats() -> dict[str, int]                               # 全局计数
nat.tenant_stats("alpha") -> dict                           # 单租户计数（含配额）
nat.tenant_ids -> tuple[str, ...]
nat.now -> int
```

`AllocationResult` 与 `Mapping` 带 `tenant` 字段；`TranslationResult` 带
`tenant`（命中映射时为其租户 ID，未定位到映射时为 `None`）。基线模式下
命中映射的租户 ID 为内部空串（`DEFAULT_TENANT_ID`）。

`advance` 的返回：基线模式为租户内裸 key 列表（旧形状不变）；多租户模式
为完整身份 `(tenant_id, key)` 列表，使两家相同 key 也能区分。均按升序。

`TranslationResult.accepted=True` 时 `rewritten` 为改写后的 `FiveTuple`
（UDP，protocol=17）；否则 `reason` 为 `DropReason` 之一：
`NO_MAPPING` / `STALE_GENERATION` / `PEER_MISMATCH` / `DEST_MISMATCH`。

## 错误语义

所有异常继承 `NATError`：

| 异常 | 含义 | 状态影响 |
|---|---|---|
| `ValidationError` | 非法输入（类型/取值/越界/时钟回退/批内重复 key/未知租户/租户表配置冲突等） | 在任何变更之前抛出，状态不变 |
| `QuotaExceededError` | 租户活跃配额不足（候选时刻回收过期后仍超限），带 `tenant/active/requested/limit`；**不是**端口问题 | 整体回滚，状态不变 |
| `PortExhaustionError` | 该租户子集全扫后容量不足（证明无解），带 `tenant/needed/available/pool_size` | 整体回滚，状态不变 |
| `SearchBudgetExhaustedError` | 共享搜索预算耗尽（未证明无解），带 `tenant/budget/inspected/needed/found` | 整体回滚，状态不变 |

输入校验规则（全库统一）：整数参数只接受精确 `int`；**`bool` 一律拒绝**；
`float`（含 `3.0`）一律拒绝，因此 **NaN/Infinity 在类型层即被拒绝**；
IPv4 只接受规范点分十进制（无前导零）；租户 ID 只接受非空字符串且必须在
租户表内。错误消息均带字段名与实收值，可定位；不做任何静默纠正。

## 输入上限

| 参数 | 上限 |
|---|---|
| 端口 | 1..65535 |
| 端口池 / 租户子集大小 | 1..65535（`MAX_POOL_SIZE`），且各自无重复 |
| 租户 ID | 非空字符串，租户表内唯一 |
| 单批分配请求数 | `MAX_BATCH_REQUESTS` = 65535；跨租户批内 `(tenant,key)` 不重复 |
| `max_active_mappings` | 1..65535 |
| 时间类整数（`at`/`advance`/`lifetime`/`quarantine` 等） | 0..2^63-1（`MAX_TIME`），且 `now + lifetime` 不得溢出 |
| `generation` | 0..2^63-1 |

## 精度说明（误差口径）

本库**不产生浮点结果**：所有计算（端口选择、过期判定、隔离判定、配额计数、
generation 比较）均为精确整数运算，比较采用严格不等式
（`now >= expires_at` 过期、`now >= released_at + Q` 解除隔离、
`active + new > max_active` 超配额），边界行为由
`tests/test_tenants.py` 与 `tests/test_contract.py` 中的边界用例逐点固定，
无容差。

## 设计取舍

- **纯函数规划 + 一次性提交**：所有批量分配把"校验/过期规划/配额/端口规划"
  与"状态提交"分开，从结构上保证失败即零副作用，而非事后补偿回滚。
- **配额先于端口**：配额检查在任何端口扫描之前，因此"配额不足"永远不会被
  报告为端口耗尽；配额错误按租户 ID 升序报告，结果确定。
- **预算按实际检查计数且跨租户共享**：被占用/隔离而跳过的端口也消耗计数，
  与基线口径一致；预算小但端口空闲时仍可能先耗尽预算（未证明无解）。
- **复用不刷新、不占配额**：`allocate` 命中已有映射只复用，不刷新过期时间；
  只有成功的包改写刷新（模拟真实流量保活）。
- **入站无租户参数**：外端口子集互不重叠，租户只能由外端口反解；出站/查询/
  释放没有可反解的外端口，必须显式声明租户作用域。
- **默认租户保留空串 ID**：用户租户 ID 强制非空，因此基线模式与多租户模式
  不可能在 ID 层混淆；多租户模式下省略租户直接报错。
- **参考实现独立**：`tests/reference_nat.py`（单租户）与
  `tests/reference_tenant_nat.py`（多租户）都只用字典/元组重写同一契约，
  不导入被测核心；差分测试逐操作比对公开结果与规范化状态签名。

## 已知限制

- 仅 UDP（protocol 固定 17）；仅地址依赖映射 + 地址依赖过滤，不含
  端口依赖/锥形 NAT、hairpin、ALG、分片、ICMP 等行为。
- 租户表构造后固定：不支持在线新增/删除租户、迁移映射或重新划分子集。
- 租户子集不要求覆盖总池：未划归任何租户的端口永远不可被分配。
- 单实例、单线程；状态只在内存中，无持久化。
- 端口分配为"最小空闲"策略的线性扫描，复杂度 O(子集大小之和)；
  本题上限（65535）下足够。
- 出站方向无映射时**丢弃**而非隐式建映射（建映射必须显式 `allocate`）。
- 时钟接近 `MAX_TIME` 时（`now + lifetime` 溢出）抛 `ValidationError`。

## 目录

```
adnat/            本题库（可导入）
  __init__.py     公开导出
  model.py        冻结数据结构 + NATConfig / TenantConfig
  errors.py       异常层级（含 QuotaExceededError）
  core.py         AddressDependentNAT 核心（单/多租户）
  _validate.py    输入校验原语
tests/
  test_contract.py           基线契约测试（手工期望值）
  test_tenants.py            多租户契约测试（隔离/配额/回滚/边界）
  test_differential.py       基线差分（核心 vs 独立字典参考）
  test_tenant_differential.py 多租户随机差分（含同址隔离/批量失败）
  reference_nat.py           单租户独立字典参考（测试 oracle）
  reference_tenant_nat.py    多租户独立字典参考（测试 oracle）
demo.py           固定输入演示（两租户 + 一次真实跨租户批量失败）
```
