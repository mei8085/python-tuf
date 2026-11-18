# 冻结时间窗、回滚保护与离线缓存过期之间的信任边界

**对象**：python-tuf `7.0.1`，commit `8e8a78a113b5d691672af4549d0a7abefe92b055`（分支 `task/157`）
**方法**：只读源码 + 仓库自带测试夹具（`tests/repository_simulator.py`、`tests/repository_data/`）+ 最小本地样本。
所有样本均以 `python -I` 在独立 venv（`tuf 7.0.1` editable、`securesystemslib 1.6.0`、`freezegun 1.5.5`）中执行；
仓库原有 206 个测试在改动前全部通过（`python -m unittest discover -s tests`，`OK`）。

> 说明：下文的 "T0" 是 `Updater` 对象被构造的时刻，不是 `refresh()` 被调用的时刻。这是本文的核心。

---

## 0. 结论摘要

1. **冻结窗口在 `TrustedMetadataSet.__init__` 里就固定了**：`reference_time = datetime.now(UTC)`
   （`tuf/ngclient/_internal/trusted_metadata_set.py:119`），而 `Updater.__init__` 只构造一次
   `TrustedMetadataSet`（`tuf/ngclient/updater.py:145-147`）。此后所有过期判断
   （root/timestamp/snapshot/delegated targets）都比对这个**构造时刻**，而不是 `refresh()` 或
   `get_targetinfo()` 的墙钟时间。长生命周期客户端因此拥有一个长度不受限的"时间窗"。
2. **缓存失去信任的时刻不是单一时刻，而是三条互相独立的轴**：
   - *过期轴*：缓存字节本身没有"上次在线验证时间"，只有元数据里仓库签名的 `expires`；
     `reference_time` 被冻住后，过期轴失效（样本 A、样本 3）。
   - *回滚轴*：唯一的下界是本地缓存里的 `timestamp.json` / `snapshot.json` 版本号
     （`trusted_metadata_set.py:249-269`、`340-356`）。缓存缺失/损坏/被清理即下界丢失（样本 B）。
   - *完整性轴*：本地 snapshot 以 `trusted=True` 载入，**跳过 timestamp 里的 hash 钉**
     （`updater.py:459`、`trusted_metadata_set.py:330-333`）；本地 targets 仍受 snapshot 的
     length/hash 约束（`trusted_metadata_set.py:428-434`）。缓存目录是否可写决定了这条轴有多硬。
3. **仓库没有持久化回滚下界，也没有离线复验 API**：`refresh()` 无条件下载 timestamp
   （`updater.py:442-445`），同一个 `Updater` 只能 refresh 一次（`updater.py:163`，
   `trusted_metadata_set.py:196/239/322/415` 的 `RuntimeError`）。离线 + 过期缓存 = 完全不可用；
   离线 + 未过期缓存 = `DownloadError`，除非应用自己用 `FetcherInterface` 把本地缓存伪装成远端。
4. **可实现、且只用公开原语的离线复验判据**：新的 `TrustedMetadataSet`（新 `reference_time`）
   + 从内嵌 bootstrap root 重验 root 链 + `trusted=False` 的 timestamp→snapshot hash 钉
   + 缓存外的持久化版本下界 + 全有或全无的缓存提交。见第 4 节与可运行样本。

---

## 1. 长生命周期客户端的调用链

### 1.1 构造期：信任锚与时间锚同时被固定

```
Updater.__init__                         tuf/ngclient/updater.py:107-149
├─ bootstrap is None                     :140-142   ← 用缓存 root.json 当信任锚（不推荐，但被允许）
├─ TrustedMetadataSet(bootstrap, ...)    :145-147
│   └─ reference_time = datetime.now()   trusted_metadata_set.py:119   ← 时间锚，只此一次
├─ _persist_root(root.version, bootstrap):148       ← 写 root_history/N.root.json
└─ _update_root_symlink()                :149       ← root.json -> root_history/N.root.json
```

关键点：**时间锚在构造期确定，早于任何网络 I/O、早于任何缓存读取、早于 `refresh()`**。
构造函数本身不做任何过期检查（`_load_trusted_root` 注释明确说过期初始 root 也算有效，
`trusted_metadata_set.py:454-466`）。

### 1.2 `refresh()`：root → timestamp → snapshot → targets

```
Updater.refresh()                        updater.py:156-183
├─ _load_root()                          :180 / :387-431
│   ├─ for v in cached root_history      :400-412   （先缓存，签名/版本不对就用远端）
│   ├─ download v.root.json              :415-422
│   │   └─ TrustedMetadataSet.update_root:178-214
│   │       ├─ 必须是 root.version + 1   :202-206
│   │       ├─ 旧 root 验签新 root       :199-201 → _load_from_metadata:487-491
│   │       └─ 新 root 用自己再验签一次  :208-209
│   └─ HTTP 403/404 => "没有更新的 root" :424-428  （其他下载错误直接抛出）
├─ _load_timestamp()                     :181 / :433-453
│   ├─ 读本地 timestamp.json             :435-437
│   ├─ 无条件下载远端 timestamp          :442-445   ← 没有任何"离线/只用缓存"分支
│   ├─ 版本相等 => 丢弃新件，保留旧件    :446-451
│   └─ 持久化 timestamp.json             :453       ← 先于 snapshot 落盘
├─ _load_snapshot()                      :182 / :455-473
│   ├─ 读本地 snapshot.json, trusted=True:457-460   ← 跳过 timestamp 的 hash 钉
│   └─ 失败则按 timestamp.snapshot_meta 下载:461-473
└─ _load_targets("targets", "root")      :183 / :475-511
    ├─ 读本地 targets.json → 验签 + snapshot 版本/hash（trusted 默认 False）
    └─ 失败则下载（consistent_snapshot 时用版本前缀）
```

### 1.3 使用期：`get_targetinfo()` / `find_cached_target()` / `download_target()`

```
get_targetinfo(path)                     updater.py:193-221
├─ if "targets" not in trusted_set: refresh()   :219-220   ← refresh 成功后就再也不刷新
└─ _preorder_depth_first_walk()          :221 / :513-581
    └─ _load_targets(role, parent)       :542
        ├─ 已加载过 => 直接返回内存对象  :479-480
        └─ 未加载 => 本地/远端           :482-511   ← 委派角色是"首次访问时才拉取"

find_cached_target(targetinfo)           updater.py:223-251
└─ 只做 targetinfo.verify_length_and_hashes()  :246-249   ← 不接触任何元数据

download_target(targetinfo)              updater.py:253-313
└─ targetinfo.verify_length_and_hashes() :303-310         ← 同上
```

两个容易被忽略的后果：

- `get_targetinfo()` 一旦成功，后续调用**不会重新检查过期**：它只判断 `Targets.type` 在不在
  trusted set 里（`updater.py:219`），而 trusted set 的内存对象不会随时间变化。
- `_load_targets()` 对**委派角色**是惰性的：顶层 `refresh()` 不下载委派角色
  （`updater.py:167-169` 的 docstring 也说明了）。首次访问委派角色可能发生在 refresh 之后很久，
  但过期判断仍用 `reference_time`（`trusted_metadata_set.py:446-447`）。
- `find_cached_target()` / `download_target()` 只信任调用者递进来的 `TargetFile` 对象，
  不验证它是否仍属于"当前可信元数据"（样本 6）。

---

## 2. 问题 1：冻结窗口在哪里生效

### 2.1 唯一的时钟采样点

```python
# tuf/ngclient/_internal/trusted_metadata_set.py:117-119
self._trusted_set: dict[str, Signed] = {}
self._trusted_delegations: set[tuple[str, str]] = set()
self.reference_time = datetime.now(UTC)
```

`reference_time` 是**实例属性**，只在 `TrustedMetadataSet.__init__` 里赋值一次，仓库内没有任何
重新赋值的地方（`grep reference_time` 的全部命中：定义处 + 4 个读取处 + 测试）。`Updater` 在
`__init__` 里创建它（`updater.py:145-147`），之后既没有 setter，也没有 `UpdaterConfig` 选项能注入时钟
（`tuf/ngclient/config.py:52-60` 只有长度/次数/UA/envelope 配置）。

### 2.2 四个检查点

| 检查 | 位置 | 被检查对象 | 不通过时 |
|---|---|---|---|
| final root 过期 | `trusted_metadata_set.py:241-243` | `root.expires` | `ExpiredMetadataError` |
| final timestamp 过期 | `:282-286`（由 `update_timestamp:278`、`update_snapshot:326`、`update_delegated_targets:419` 调用） | `timestamp.expires` | `ExpiredMetadataError` |
| final snapshot 过期 / 版本不符 | `:369-379`（`update_snapshot:365`、`update_delegated_targets:419`） | `snapshot.expires`、`snapshot.version == timestamp.snapshot_meta.version` | `ExpiredMetadataError` / `BadVersionNumberError` |
| 委派 targets 过期 | `:446-447` | `new_delegate.expires` | `ExpiredMetadataError` |

四者全部用 `self.reference_time`，没有例外。注意 **root 过期只在 `update_timestamp()` 中被检查**
（`:241-243`）：一个从不调用 `refresh()`、只调用 `get_targetinfo()` 的路径也会经过这里（隐式 refresh），
但如果 trusted set 里已有 targets，则连这一步也不会再发生。

### 2.3 时间窗的真实长度由"对象存活时间"决定，而不是由元数据决定

- `refresh()` 的 docstring 说 "A `refresh()` can be done only once during the lifetime of an Updater"
  （`updater.py:163`）。重复调用会在 `update_timestamp()` 处抛
  `RuntimeError: Cannot update timestamp after snapshot`（`trusted_metadata_set.py:238-239`），
  因为 snapshot 已经在 trusted set 里。
- 因此**同一个 `Updater` 没有任何办法把 `reference_time` 推进到"现在"**。长生命周期进程要么
  接受冻结的时间窗，要么每次校验都重建 `Updater`（重建会重新读盘、重写 root_history、重新下载
  timestamp）。
- 冻结窗口没有上界：只要进程不退出、不重建对象，`reference_time` 永远停在 T0。

### 2.4 仓库测试只覆盖"同一个 `freezegun` 窗口内构造并 refresh"

`tests/test_updater_top_level_update.py` 的所有过期测试都通过 `_init_updater()`（`:77-94`）在
`freezegun.freeze_time(...)` 块**内部**构造 Updater 并立即 refresh，例如：

```python
# tests/test_updater_top_level_update.py:353-357
patcher = freezegun.freeze_time(datetime.now(UTC) + timedelta(days=18))
with patcher, self.assertRaises(BadVersionNumberError):
    self._run_refresh()          # 这里 _run_refresh 内部会构造新的 Updater
```

所以测试证明了"在给定 reference_time 下判断正确"，但**没有测试 reference_time 与 refresh 墙钟时间
分离**的情形。这正是本文样本 A/3 的空间。

### 2.5 冻结窗口最小复现（样本 A）

只用仓库夹具 `tests.repository_simulator.RepositorySimulator`：

```python
import tempfile
from datetime import UTC, datetime, timedelta
import freezegun
from tests.repository_simulator import RepositorySimulator
from tuf.ngclient import Updater

MD, TG = "https://example.com/metadata/", "https://example.com/targets/"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)

with freezegun.freeze_time(T0):
    sim = RepositorySimulator()
    sim.root.expires = T0 + timedelta(days=3650)
    sim.root.version += 1
    sim.publish_root()
    for r in (sim.timestamp, sim.snapshot, sim.targets):
        r.expires = T0 + timedelta(days=7)
    sim.add_target("targets", b"app v1", "app.bin")

    # 长生命周期服务在启动时构造 Updater，reference_time 在此冻结
    service = Updater(
        tempfile.mkdtemp(), MD, tempfile.mkdtemp(), TG, sim,
        bootstrap=sim.signed_roots[-1],
    )

with freezegun.freeze_time(T0 + timedelta(days=40)):
    service.refresh()          # 首次 refresh 发生在 40 天之后
    info = service.get_targetinfo("app.bin")
    print("T0+40d: refresh accepted metadata that expired at T0+7d;",
          "installed", open(service.download_target(info), "rb").read())
```

实测输出：

```
T0+40d: refresh accepted metadata that expired at T0+7d; installed b'app v1'
```

同一时刻、同一仓库、同一缓存，用一个**新建**的 `Updater` 会得到相反的结论：

```
fresh Updater at the same instant -> ExpiredMetadataError: timestamp.json is expired
```

（对照实验见 `/tmp/tuf_samples/report/r1_freeze_and_eviction.py` 的完整版本，含缓存被清理的场景：
T0 预热缓存 → T0+40d 删除 `timestamp/snapshot/targets.json` → 同一 service 对象 refresh 成功并安装
过期元数据所指的 target。）

### 2.6 分类

| 结论 | 类型 |
|---|---|
| 一次 refresh 工作流内部所有过期检查使用同一个 `reference_time`（原子时钟语义） | **源码已保证** |
| 过期检查用的是"构造时刻"而不是"本次 refresh 时刻" | **源码行为**，但 `Updater` 的公开文档没有任何提示；对长生命周期用法构成 **当前缺口** |
| 没有 API/config 可以刷新 reference_time，重复 `refresh()` 直接 `RuntimeError` | **当前缺口**（必须重建对象，且重建会重写缓存） |
| `get_targetinfo()` 成功后不再重新验证过期 | **当前缺口**（内存状态无 TTL） |
| 两个 Updater 实例同时使用同一 metadata_dir 不受支持（`updater.py:33-35`），因此"重建对象"不是零成本 | **源码已保证的限制**，属于部署约束 |

---

## 3. 问题 2：缓存何时失去信任

缓存不是一个整体：它由多个独立文件（`root.json` 符号链接、`root_history/N.root.json`、
`timestamp.json`、`snapshot.json`、`targets.json`、委派角色文件、target 文件）组成，
每个文件有自己的信任来源和失败模式。

### 3.1 过期轴：缓存字节里没有"验证时间"

已验证的元数据被原样落盘（`_persist_metadata:331-340`、`_persist_root:342-350`），文件里只有
仓库签名的 `expires`。客户端的"我是什么时候验证它的"只存在于 `reference_time` 这个**内存变量**里。
进程重启 = 这个信息消失；进程不重启 = 它永远停在 T0。

因此：
- **重启**后构造成员会重新采样时钟 → 过期轴恢复（样本 B 的 "fresh Updater" 行）。
- **不重启**则过期轴永久失效（样本 3、样本 A）。

### 3.2 回滚轴：下界是"缓存里恰好还在的旧文件"

`update_timestamp()` 的校验（`trusted_metadata_set.py:249-269`）：

```python
if Timestamp.type in self._trusted_set:                 # 只有本地 timestamp 成功载入才有下界
    if new_timestamp.version < self.timestamp.version:  # timestamp 版本不能降
        raise BadVersionNumberError(...)
    if new_timestamp.version == self.timestamp.version:
        raise EqualVersionNumberError                  # 同版本 -> 保留旧的
    if new_timestamp.snapshot_meta.version < self.timestamp.snapshot_meta.version:
        raise BadVersionNumberError(...)               # snapshot 版本不能降
```

`update_snapshot()` 的校验（`:340-356`）：不允许删除 snapshot.meta 里的任何角色、不允许角色版本降低。
`update_delegated_targets()`（`:440-444`）要求 targets 版本严格等于 snapshot 记录的版本。

这些校验的**前提都是 `Timestamp.type in self._trusted_set` / `Snapshot.type in self._trusted_set`**。
本地文件缺失或验签失败时，`Updater._load_timestamp()` 只是 `logger.debug` 后继续
（`updater.py:435-440`，`except (OSError, RepositoryError)`），没有任何用户可见的错误：

```python
try:
    data = self._load_local_metadata(Timestamp.type)
    self._trusted_set.update_timestamp(data)
except (OSError, exceptions.RepositoryError) as e:
    logger.debug("Local timestamp not valid as final: %s", e)
# 无论本地是否成功，都继续下载远端
```

`_load_snapshot()` 同理（`:457-463`）；`_load_targets()` 同理（`:482-491`）。区别在于 targets 有
snapshot 版本作为第二道约束，而 timestamp 的下界一旦丢失就只剩 snapshot 的版本下界。

所以缓存失去回滚信任的精确时刻是：**当本地 `timestamp.json` 与 `snapshot.json` 同时不可用/不可信时**。
只剩 `snapshot.json` 时，snapshot 版本仍能挡住一部分回滚（样本 2b 的 A 分支），但 timestamp 版本下界
和"snapshot 版本不能降"的约束都消失了。

### 3.3 完整性轴：`trusted=True` 是有意跳过 hash 钉

```python
# tuf/ngclient/updater.py:457-460
data = self._load_local_metadata(Snapshot.type)
self._trusted_set.update_snapshot(data, trusted=True)
```

```python
# tuf/ngclient/_internal/trusted_metadata_set.py:330-333
# Verify non-trusted data against the hashes in timestamp, if any.
# Trusted snapshot data has already been verified once.
if not trusted:
    snapshot_meta.verify_length_and_hashes(data)
```

`trusted` 参数的设计理由是："新 snapshot 可能被下载，而 timestamp 里只有当前 snapshot 的 hash"。
但 `Updater` 对**任何**在磁盘上找到的 `snapshot.json` 都传 `trusted=True`——它无法知道这个文件是不是
"上一次由自己验证过的同一串字节"。因此如果缓存目录可被其他进程写，攻击者可以放入一个**签名有效、
版本相同、但字节不同**的 snapshot（仓库 equivocation），timestamp 的 hash 钉会被跳过。
签名和版本检查仍然生效（`:335-356`）。

仓库自己的测试已经把这个行为固定下来：
`tests/test_updater_top_level_update.py:678-706` 的
`test_snapshot_rollback_with_local_snapshot_hash_mismatch` 明确构造 "本地 snapshot 与 timestamp hash
不匹配但仍被当作 trusted 载入"。文档也提醒 `metadata_dir` "writable by design"，不应用作 bootstrap root
的存放位置（`docs/INSTALLATION.rst:70-77`）。

实测（样本 13）：把缓存里的 snapshot 换成一个重新序列化、签名仍有效、但字节与 timestamp 钉住的 hash
不同的版本，`refresh()` 接受并使用它；而同一个 hash 钉对同一串字节会抛
`LengthOrHashMismatchError`。

### 3.4 写入轴：refresh 不是跨文件事务

- `timestamp.json` 在验签后立即 `os.replace` 落盘（`updater.py:453`），snapshot 在其后
  （`:473`），targets 更后（`:509`）。每个文件内部是原子的（`_persist_file:352-369`），
  **跨文件不是**。
- 失败场景（样本 12）：timestamp v2 落盘成功、snapshot 下载失败 → 缓存变成 `t=2, s=1`。
  此后任何离线复验都会在 `_check_final_snapshot()` 处因版本不符失败（`trusted_metadata_set.py:369-379`），
  即使**失败前**的 `t=1, s=1` 缓存是自洽可用的。
- 反向的不一致（`t` 旧、`s` 新）不会发生，因为 snapshot 只在 timestamp 之后写。

### 3.5 root 轴：`root_history` 是唯一跨代下界，但也有边界

- 每次成功 `update_root` 后都会 `_persist_root`（`updater.py:421-422`），且用版本号命名；
  `_load_root()` 优先从 `root_history` 读（`:400-412`）。这保证了"看过 root v3 的客户端不会回退到 v1"。
- 但 root 链的锚点仍然是 `Updater.__init__` 收到的 bootstrap（`updater.py:140-147`）。空缓存的部署
  从内嵌 root v1 开始，如果 v2 从未被看到，v1 的旧密钥签名的旧 timestamp 仍然有效。
- 样本 15 实测：root v2 轮换 timestamp 密钥后，热缓存客户端拒绝旧 timestamp
  （`UnsignedMetadataError`），而空缓存客户端接受同一份旧 timestamp 并回滚到 targets v2。
- `_load_root()` 只把 HTTP **403/404** 当作"没有更新 root"（`:424-428`）。`DownloadError` 或 503 会
  直接中止整个 refresh（样本 10），即使缓存本身完全可用。

### 3.6 target 轴：`TargetFile` 对象没有生命周期

`find_cached_target()` 和 `download_target()` 只校验调用者传入的 `TargetFile` 的 length/hash
（`updater.py:246-249`、`303-310`）。它们不检查：
- 这个 `TargetFile` 是否来自当前 trusted set 的 targets；
- 该 targets 元数据是否已过期；
- 该 target 是否在更新的 targets 中已被删除/替换。

样本 6：targets v3 删除了 `app.bin`，`get_targetinfo()` 返回 `None`，但 day-0 拿到的旧 `TargetFile`
仍然可以下载并命中缓存。样本 4：完全离线时，`find_cached_target(old_info)` 仍返回路径——它只证明了
"文件与旧 TargetFile 一致"，没有证明"旧 TargetFile 仍可信"。

### 3.7 缓存失去信任的判定表

| 事件 | 过期轴 | 回滚轴 | 完整性轴 | 结果 |
|---|---|---|---|---|
| 进程重启（新 `Updater`） | 恢复（新时钟） | 保留（磁盘） | 保留 | 缓存重新可信（除非过期） |
| 同一 `Updater` 存活超过 `expires` | **失效** | 保留（内存） | 保留 | 过期元数据继续被使用（样本 3/A） |
| 删除 `timestamp.json` | — | snapshot 版本下界仍在 | — | 部分失去；close 场景可被 snapshot 挡住（样本 2b-A） |
| 删除 `timestamp.json` + `snapshot.json` | — | **完全失效** | — | 接受任意未过期签名状态（样本 B/2b-B/11） |
| 缓存目录被第三方写 | — | 版本仍需非降 | **snapshot hash 钉失效** | 仓库 equivocation 可达（样本 13） |
| refresh 中途失败 | 不变 | 不变 | 变 | 缓存跨层不一致 → 离线不可用（样本 12） |
| 空缓存 + 未轮换 root | — | **无下界** | — | 旧签名状态可重放（样本 15） |

---

## 4. 问题 3：如何在离线更新中复验

### 4.1 仓库现有的原语

`TrustedMetadataSet` 是纯内存/纯字节的（模块 docstring 明确说 filesystem 和 network IO 不在其中，
`trusted_metadata_set.py:4-11`），因此可以完全离线使用：

```python
# 新实例 = 新 reference_time，这一点是离线复验的关键
ts = TrustedMetadataSet(bootstrap_root_bytes, EnvelopeType.METADATA)
for v in sorted_cached_root_versions:          # 必须连续、从 bootstrap 版本 +1 开始
    ts.update_root(open(f"{md}/root_history/{v}.root.json", "rb").read())
ts.update_timestamp(open(f"{md}/timestamp.json", "rb").read())
ts.update_snapshot(open(f"{md}/snapshot.json", "rb").read())   # trusted=False！
ts.update_targets(open(f"{md}/targets.json", "rb").read())
```

### 4.2 可运行的参考复验器（样本，已实测）

```python
import json, os
from datetime import UTC, datetime
from tuf.api.exceptions import RepositoryError
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

def read(path):
    with open(path, "rb") as f:
        return f.read()

def revalidate_offline(md_dir: str, bootstrap: bytes,
                       floor: dict[str, int], now: datetime):
    ts = TrustedMetadataSet(bootstrap, EnvelopeType.METADATA)

    # 1) root 链：只接受连续版本，任何 gap 都 fail closed
    root_dir = os.path.join(md_dir, "root_history")
    versions = sorted(int(n.split(".")[0]) for n in os.listdir(root_dir)
                      if n.endswith(".root.json"))
    for v in versions:
        if v <= ts.root.version:
            continue
        if v != ts.root.version + 1:
            raise RepositoryError(f"gap in cached root chain at v{v}")
        ts.update_root(read(os.path.join(root_dir, f"{v}.root.json")))

    # 2) timestamp -> snapshot -> targets，全部按当前时间重新检查过期
    ts.update_timestamp(read(os.path.join(md_dir, "timestamp.json")))
    ts.update_snapshot(read(os.path.join(md_dir, "snapshot.json")))  # trusted=False
    ts.update_targets(read(os.path.join(md_dir, "targets.json")))

    accepted = {"root": ts.root.version, "timestamp": ts.timestamp.version,
                "snapshot": ts.snapshot.version, "targets": ts.targets.version}

    # 3) 缓存外的持久化下界：缓存丢失不能让版本回退
    for role, ver in accepted.items():
        if ver < floor.get(role, 0):
            raise RepositoryError(
                f"rollback vs persistent floor: {role} v{ver} < v{floor[role]}")
    return accepted
```

实测（T0 在线 refresh 一次并记录 floor；T0+1d 断网）：

```
T0     online refresh; floor = {'timestamp': 3, 'snapshot': 3, 'targets': 2, 'root': 2}
offline, same cache, +1d   : {'root': 2, 'timestamp': 3, 'snapshot': 3, 'targets': 2}
offline replay of day 0    : RepositoryError: rollback vs persistent floor: timestamp v2 < v3
offline, +31d (expired)    : ExpiredMetadataError: timestamp.json is expired
```

注意这是**在 `Updater` 之外**的复验：`Updater` 本身没有离线入口，直接 `refresh()` 时
`_load_timestamp()` 永远会发网络请求（`updater.py:442-445`），断网就是 `DownloadError`（样本 4/10）。

### 4.3 离线更新仍可接受的修复判据

以下判据按"必须同时满足"列出；每条都给出可验证的失败模式。

**C1. 时间锚必须在每次校验时重新采样**
- 判据：`reference_time` 在 `refresh()`/`revalidate_offline()` 入口采样，不在构造函数采样；
  或提供 `refresh(reference_time=...)`。
- 反例：样本 A（T0 构造、T0+40d 首次 refresh 仍接受 T0+7d 过期元数据）。
- 验证：构造 Updater → 时钟前进 > `expires` → 调用 → 必须抛 `ExpiredMetadataError`。

**C2. 离线可用性必须由"上次在线成功时间"界定，而不是由元数据本身界定**
- 判据：维护持久化的 `last_successful_online_refresh`（写入需原子 + 仅在线成功 refresh 后更新），
  离线复验要求 `now - last_successful_online_refresh <= max_offline_age`
  **并且** root/timestamp/snapshot/targets 全部 `now < expires`。
- 理由：元数据的 `expires` 是仓库侧的承诺；离线的风险是"我手里的世界已经过时"，
  这两个时间量不同。`UpdaterConfig` 目前没有任何这类配置（`config.py:52-60`）。
- 反例：样本 12 的 `t=2, s=1` 缓存，签名全部有效，但语义上已经不一致。

**C3. 回滚下界必须持久化在可丢失缓存之外**
- 判据：对 root/timestamp/snapshot/每个 targets 角色维护单调不减的版本下界，
  存储位置与 `metadata_dir` 分离（只读挂载、独立小文件、系统 keyring 等），
  只在**完整成功**的在线 refresh 之后更新；离线或失败时只读不写。
- 允许的例外：root key 轮换触发的 fast-forward recovery（仓库已有测试
  `test_new_timestamp_fast_forward_recovery`、`test_new_snapshot_fast_forward_recovery`、
  `test_new_targets_fast_forward_recovery`，`tests/test_updater_top_level_update.py:432-457/513-544/621-649`）
  必须在**新 root 已验证**的前提下手动/显式重置下界。
- 反例：样本 B（删除 `timestamp.json` + `snapshot.json` 后接受 v2 replay）、样本 15（空缓存接受旧 root 链）。
- 验证：清空/损坏缓存后重放旧签名状态 → 必须失败；正常在线 refresh 后下界必须增加。

**C4. 缓存必须按"代"提交，离线只接受完整的一代**
- 判据：一次 refresh 的所有文件写进一个新目录（或先写临时文件 + 单个 manifest/rename 提交），
  读取时校验 manifest 与文件集一致；不一致视为"无缓存"，而不是"部分可用"。
- 反例：样本 12（timestamp 先落盘、snapshot 失败 → 离线复验 `BadVersionNumberError`）。
- 说明：`_persist_metadata()` 已经保证单文件原子（`updater.py:352-369`），缺的是跨文件事务。

**C5. 离线复验不能跳过 hash 钉**
- 判据：离线调用 `update_snapshot(..., trusted=False)`；`trusted=True` 只允许用于
  "刚刚在同一个进程里下载并验证过这串字节"的情况。
- 理由：`trusted=True` 的唯一设计目的是"还要去下载更新版本"，离线时这个理由不存在。
- 反例：样本 13（重新序列化的同版本 snapshot 被接受）。
- 附带判据：targets 和委派角色也必须用默认的 `trusted=False` 路径
  （`update_delegated_targets` 里的 `meta.verify_length_and_hashes(data)`，`trusted_metadata_set.py:428-434`）。

**C6. 只接受"元数据当前仍然列出"的 target**
- 判据：离线可用的 target 必须由本次复验后的 `trusted_set.targets`（或复验后的委派角色）重新解析；
  不接受跨 refresh 缓存的 `TargetFile`。文件内容用该 `TargetFile` 的 length/hash 验证。
- 反例：样本 6（targets v3 已删除的 target 仍可下载）。
- 说明：`find_cached_target()` 的签名本身没问题，问题在调用者可以传入任意旧 `TargetFile`。
  建议在应用层加一层 `TargetFile` 与 `(role, version)` 的绑定，或每次从新 trusted set 重新 `get_targetinfo()`。

**C7. 失败必须 fail closed，并且"离线"要能被显式识别**
- 判据：缓存缺失/损坏/版本不符/时钟异常 → 拒绝更新，不回退到"用缓存里剩的"。
  fetcher 的离线错误应与"资源不存在"区分：`_load_root()` 目前只接受 403/404 作为链尾
  （`updater.py:424-428`），否则整个 refresh 中止（样本 10）。若要做离线模式，
  应由应用显式调用离线复验器，而不是让 `refresh()` 在 `DownloadError` 上碰运气。
- 反例：`_load_timestamp()`/`_load_snapshot()`/`_load_targets()` 对本地读取失败只 `logger.debug`
  （`updater.py:438-440/461-463/489-491`），用户无法从异常类型上区分"缓存没有"与"缓存坏了"。

**C8. 时钟本身要可信**
- 判据：不要用文件 mtime 或单调计数器替代墙钟（单调计数器无法跨重启判断过期）；
  若部署无法信任系统时钟，离线策略应退化为"只允许在 `max_offline_age` 内使用，
  且该值由可信的、单调的在线时间累积得到"。
- 说明：仓库没有任何时钟抽象（`UpdaterConfig` 无 clock 注入），因此 C1/C2 需要应用层或上游 API 变更。

### 4.4 判据与仓库现状的对照

| 判据 | 仓库现状 | 补齐工作量 |
|---|---|---|
| C1 时间锚每次采样 | 构造期采样，无法更新 | 小：`refresh()` 增加可选 `reference_time` 或重建 `TrustedMetadataSet` |
| C2 离线有效期 | 无配置、无持久化 | 中：应用层可实现；上游可加 `UpdaterConfig.max_offline_age` |
| C3 持久化回滚下界 | 无 | 中：可完全在应用层用 `TrustedMetadataSet` 返回值实现 |
| C4 原子代提交 | 单文件原子，跨文件非原子 | 中：改用 generation dir + 一个 manifest |
| C5 离线不跳过 hash 钉 | `trusted=True` 硬编码在 `updater.py:459` | 小：离线路径直接用 `TrustedMetadataSet` |
| C6 target 绑定 | 无 | 小：应用层每次重新解析 |
| C7 fail closed | 本地错误被吞、离线语义不明 | 小-中：错误分类 + 显式离线 API |
| C8 可信时钟 | 无抽象 | 中：应用层或上游注入 clock |

---

## 5. 攻击顺序（至少两个，均用仓库夹具实测）

### 攻击顺序 A：长生命周期对象 + 缓存淘汰 → 在冻结窗口内安装过期元数据

**前提**（均为常见部署事实，不需要密钥泄露）：
1. 服务进程在启动时构造 `Updater` 并长期持有（T0 固定 `reference_time`）。
2. 部署会清理可变缓存（tmpfs、容器重启、磁盘配额），只保留不可变的 bootstrap root。
3. 镜像/缓存层能返回 T0 时刻的合法签名元数据（CDN、对象存储版本化、被攻陷的镜像）。

**步骤**：

| 时刻 | 动作 | 代码路径 |
|---|---|---|
| T0 | 构造 `Updater`，`TrustedMetadataSet` 记录 `reference_time=T0` | `updater.py:145-147` / `trusted_metadata_set.py:119` |
| T0 | （可选）预热缓存；元数据 `expires=T0+7d` | `refresh()` |
| T0+40d | 清理 `timestamp/snapshot/targets.json` | 部署行为 |
| T0+40d | 同一对象 `refresh()`：本地无 timestamp → 下载 T0 字节 → 过期检查用 T0 | `updater.py:442-447`、`trusted_metadata_set.py:278-286` |
| T0+40d | `get_targetinfo()` + `download_target()` 安装旧 target | `updater.py:219-221`、`303-310` |

**实测输出**：

```
T0    : cache warmed, metadata expires 2026-08-08 12:00:00+00:00
T0+40d: mutable cache evicted; mirror still serves the T0 bytes
        accepted; installed b'app v1 (stale)'
        fresh Updater at the same instant: ExpiredMetadataError: timestamp.json is expired
```

**分类**：
- 源码已保证：同一个 `reference_time` 下过期判断正确；timestamp 同版本时保留旧件
  （`trusted_metadata_set.py:258-260`）。
- 依赖配置决定：清理缓存的策略、是否在启动时构造并长期持有 `Updater`、是否定期重建对象。
- 当前缺口：`refresh()`/`get_targetinfo()` 没有"用当前墙钟重新检查"的入口；`reference_time`
  不可注入也不可更新；重复 `refresh()` 是 `RuntimeError` 而不是"重新校验"。

> 更严格地说，如果服务在 T0 已经成功 refresh 过，那么即使缓存**没有**被清理，T0+40d 的
> `get_targetinfo()` 仍会从内存 trusted set 返回结果，`find_cached_target()` 仍会命中——
> 只是不会再下载新 target。样本 3 的实测：
>
> ```
> T0+40d : metadata expired at T0+7d
>   (a) long-lived Updater.get_targetinfo -> app.bin
>       find_cached_target -> .../app.bin
>   (b) second refresh() on same instance -> RuntimeError: Cannot update timestamp after snapshot
> ```

### 攻击顺序 B：部分缓存丢失 + 旧签名状态重放 → 回滚到下界之外

**前提**：
1. 客户端曾经见过更高的版本（缓存里曾经有 t3/s3/targets3）。
2. 攻击者能让某次 refresh 的本地 `timestamp.json` 和 `snapshot.json` 不可用/不可信
   （清理、权限、损坏、容器快照回滚、写坏文件）。
3. 镜像能重放 T0 的合法签名状态（版本更低但未过期）。

**步骤**：

| 时刻 | 动作 | 代码路径 |
|---|---|---|
| day 1 | 缓存 = t3/s3/targets3（含修复） | 正常 refresh |
| day 2 | 只留下 `targets.json`，删除 `timestamp.json`+`snapshot.json` |  |
| day 2 | 镜像返回 day-0 的 t2/s2/targets2 |  |
| day 2 | `_load_timestamp()` 本地失败 → 只 `logger.debug` → 接受远端 t2 | `updater.py:435-440` |
| day 2 | 无 `Timestamp.type` 在 trusted set → 回滚比较整体跳过 | `trusted_metadata_set.py:249` |
| day 2 | `_load_snapshot()` 本地失败 → 接受远端 s2；无旧 snapshot → 回滚比较跳过 | `updater.py:457-463`、`trusted_metadata_set.py:341` |
| day 2 | targets v2 与 s2 的 meta 一致 → 通过 | `trusted_metadata_set.py:440-444` |

**实测输出**：

```
day 1: cache {timestamp,snapshot,targets} = 3/3/3 (app v2)
day 2: partial cache accepted the replay; installed b'app v1 (vulnerable)'
       intact cache: BadVersionNumberError: New timestamp version 2 must be >= 3
```

完整可运行代码（只用仓库夹具）：

```python
import os, shutil, tempfile
from datetime import UTC, datetime, timedelta
import freezegun
from tests.repository_simulator import RepositorySimulator
from tuf.ngclient import Updater

MD, TG = "https://example.com/metadata/", "https://example.com/targets/"
T0 = datetime(2026, 3, 1, 12, tzinfo=UTC)

with freezegun.freeze_time(T0):
    sim = RepositorySimulator()
    for r in (sim.timestamp, sim.snapshot, sim.targets):
        r.expires = T0 + timedelta(days=30)
    sim.add_target("targets", b"app v1 (vulnerable)", "app.bin")
    sim.targets.version = 2
    sim.update_snapshot()                      # timestamp v2, snapshot v2

    md, tg = tempfile.mkdtemp(), tempfile.mkdtemp()
    Updater(md, MD, tg, TG, sim, bootstrap=sim.signed_roots[0]).refresh()
    sim.add_target("targets", b"app v2 (fixed)", "app.bin")
    sim.targets.version = 3
    sim.update_snapshot()                      # timestamp v3, snapshot v3
    Updater(md, MD, tg, TG, sim, bootstrap=sim.signed_roots[0]).refresh()

with freezegun.freeze_time(T0 + timedelta(days=2)):
    # stale mirror: rewind every field to the day-0 signed state
    sim.timestamp.version = 2
    sim.timestamp.snapshot_meta.version = 2
    sim.snapshot.version = 2
    sim.snapshot.meta["targets.json"].version = 2
    sim.targets.version = 2
    sim.add_target("targets", b"app v1 (vulnerable)", "app.bin")

    # deployment loses timestamp.json + snapshot.json (targets.json stays)
    lost = tempfile.mkdtemp()
    for f in os.listdir(md):
        src, dst = os.path.join(md, f), os.path.join(lost, f)
        shutil.copytree(src, dst) if os.path.isdir(src) else shutil.copy2(src, dst)
    os.remove(f"{lost}/timestamp.json")
    os.remove(f"{lost}/snapshot.json")

    u = Updater(lost, MD, tg, TG, sim, bootstrap=sim.signed_roots[0])
    u.refresh()
    u.download_target(u.get_targetinfo("app.bin"))
    print(open(os.path.join(tg, "app.bin"), "rb").read())
```

变体（只删 `timestamp.json`，保留 `snapshot.json`）仍会被 snapshot 版本下界拦住：

```
A (timestamp deleted): BadVersionNumberError: Expected targets.json version 2, got 3.
B (timestamp+snapshot deleted): refresh SUCCEEDED -> floor LOST
    accepted timestamp v2, targets v2
```

损坏（而不是删除）`timestamp.json` 的结果相同：`update_timestamp()` 在验签失败前不会 `_add()`，
下界同样丢失，异常被 `updater.py:438-440` 吞掉（样本 11）。

**分类**：
- 源码已保证：**只要缓存里有旧 timestamp/snapshot**，版本回滚被严格拒绝，包括本地已过期的旧件也参与比较
  （`tests/test_updater_top_level_update.py:329-394` 的 `test_expired_timestamp_version_rollback` /
  `test_expired_timestamp_snapshot_rollback`）。
- 依赖配置决定：缓存是否被外部清理、缓存目录权限、是否把 `metadata_dir` 放在易失存储上。
- 当前缺口：仓库**没有**缓存外的持久化版本下界；本地缓存读取失败被当作"没有下界"而不是"下界未知"；
  没有区分"从未见过该角色"与"曾经见过但缓存坏了"。

### 5.1 其他已实测的边界（补充）

| # | 顺序 | 实测结果 | 分类 |
|---|---|---|---|
| 1 | 同版本但不同字节的 snapshot 放入缓存（仓库 equivocation） | `refresh()` 接受，hash 钉被 `trusted=True` 跳过；同一 hash 钉对同一字节抛 `LengthOrHashMismatchError` | 源码行为（`trusted` 语义）+ 缓存可写 = 部署配置 |
| 2 | root v2 轮换 timestamp 密钥后，空缓存重放 root v1 + 旧 timestamp | 热缓存：`UnsignedMetadataError`；空缓存：接受，回滚到 targets v2 | 源码已保证"看过就不回退"；空缓存无跨代下界 = 缺口 |
| 3 | refresh 中途 snapshot 下载失败 | 缓存 `t=2,s=1`；之后离线复验 `BadVersionNumberError: Expected snapshot version 2, got 1` | 跨文件非原子 = 缺口 |
| 4 | 旧 `TargetFile` 在 targets v3 删除该 target 后继续使用 | 仍可 `download_target()` / `find_cached_target()` | API 契约未绑定 = 缺口 |
| 5 | 断网时 `refresh()` 探测 root | 只有 403/404 被当作链尾；`DownloadError`/503 中止整个 refresh | 需 fetcher/应用层配合 |
| 6 | 委派角色首次访问发生在 refresh 之后 40 天 | 过期判断用 T0，过期 33 天的委派 targets 被接受 | 冻结窗口 = 缺口 |
| 7 | 部分失败后在同一对象上重试 | 第一次失败后第二次可成功；第三次 `RuntimeError`；内存状态可能停留在 `{root,timestamp}` | 文档化的 refresh-once = 源码行为 |

---

## 6. 三个问题的直接回答

### 6.1 冻结窗口在哪里生效？

在 `TrustedMetadataSet.__init__` 的 `self.reference_time = datetime.now(UTC)`
（`tuf/ngclient/_internal/trusted_metadata_set.py:119`），由 `Updater.__init__`
（`tuf/ngclient/updater.py:145-147`）触发，整个 `Updater` 生命周期内不再更新。
四个过期检查点（`trusted_metadata_set.py:242/285/372/446`）全部使用它。
窗口的右边界不是元数据的 `expires`，而是"进程何时重建 `Updater`"。

### 6.2 缓存何时失去信任？

- **过期意义上**：缓存从未真正"失去信任"，因为信任判定只发生在写入时；
  运行时唯一的新鲜度信号是内存里的 `reference_time`。它一冻结，过期缓存就永久"有效"。
- **回滚意义上**：当 `timestamp.json` 和 `snapshot.json` 同时不可用或不可信时
  （本地下界消失，`updater.py:435-440`、`457-463`）。
- **完整性意义上**：本地 snapshot 从一开始就以 `trusted=True` 载入，timestamp 的 hash 钉不适用
  （`updater.py:459`、`trusted_metadata_set.py:332-333`）；只有签名和版本仍被检查。
- **一致性意义上**：任何一次 refresh 在 timestamp 落盘之后、snapshot/targets 落盘之前失败时
  （`updater.py:453` vs `:473`/`:509`）。

### 6.3 如何在离线更新中复验？

用新的 `TrustedMetadataSet`（因此有新的 `reference_time`）对缓存字节重放完整工作流：
root 链（从内嵌 bootstrap root、版本连续）→ timestamp → snapshot（**`trusted=False`** 以保留 hash 钉）
→ targets；再对照缓存外的持久化版本下界。判据见 4.3（C1–C8），最小实现见 4.2。
不要通过 `Updater.refresh()` 做离线复验：它无条件下载 timestamp，且没有离线分支。

---

## 7. 附：复现材料

| 样本 | 作用 |
|---|---|
| `/tmp/tuf_samples/final/attack_a.py` | 攻击顺序 A（长生命周期 + 缓存淘汰），完整可运行 |
| `/tmp/tuf_samples/final/attack_b.py` | 攻击顺序 B（部分缓存丢失 + 回放），完整可运行 |
| `/tmp/tuf_samples/report/r1_freeze_and_eviction.py` | A 的对照版（热/冷缓存、同时刻新对象） |
| `/tmp/tuf_samples/report/r2_rollback_replay.py` | B 的对照版（完整缓存 vs 部分缓存） |
| `/tmp/tuf_samples/report/r3_longlived_daemon.py` | 长生命周期对象在过期后的行为与 refresh-once |
| `/tmp/tuf_samples/report/offline_verify.py` | 离线复验器 + 持久化下界 + 过期拒绝的实测 |
| `/tmp/tuf_samples/s13_trusted_flag.py` | `trusted=True` 跳过 snapshot hash 钉 |
| `/tmp/tuf_samples/s15_root_floor.py` | root 轮换 + 空缓存的跨代回滚 |
| `/tmp/tuf_samples/s12_mixed_cache.py` | refresh 非原子导致的混合缓存 |
| `/tmp/tuf_samples/s11_corrupt_cache_floor.py` | 损坏本地 timestamp 静默丢失下界 |
| `/tmp/tuf_samples/s10_offline_root_error.py` | 离线时 root 探测的错误语义 |
| `/tmp/tuf_samples/s6_stale_targetfile.py` | 旧 `TargetFile` 脱离元数据生命周期 |
| `/tmp/tuf_samples/s3b_lazy_delegation.py` | 委派角色惰性加载 + 冻结窗口 |

所有样本只依赖仓库自带 `tests.repository_simulator` 与 `tests.repository_data`，可在仓库根目录用
`python -I <script>` 运行（需 `securesystemslib[crypto]`、`urllib3`、`freezegun`）。
