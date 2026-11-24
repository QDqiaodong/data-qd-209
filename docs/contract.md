# 有界目标数据重定位

这是调用方给定section/symbol记录的离线链接数据API，不解析或执行ELF/PE/机器代码。sections为1..100个唯一name/base/size，base整数0..1000000、size1..100000，地址半开区间不得相交。symbols为0..1000项唯一name、既有section、offset在段内、global严格bool；global只是保留声明，不改变可见性解析，符号名全局唯一，不支持弱符号。

relocations为0..2000项唯一id、既有section/symbol、offset、addend整数±1000000、width1..8字节，目标写区间必须完全在段内且同段各重定位不得重叠。值为section(symbol).base+symbol.offset+addend，必须在[0,2^(8*width))，否则整体拒绝；输出小端字节数组，负值不作补码截断。输入顺序保留，无PC相对重定位或实际二进制修改。

样例msg地址8194，2字节为[2,32]。不是代码片段管理、批量文件工具或依赖安装项目。后续多对象符号解析和不同重定位类型可沿section/symbol/relocation身份接入；当前不承诺任何真实对象格式兼容。普通字段/整数拒绝bool及未知字段。IO原子新建，拒绝已有路径及链接。

## 多对象链接 `link(data)`

独立于 `process` 的离线多对象链接入口，同样不解析或执行ELF/PE/机器代码。输入是只含 `regions`、`objects` 的JSON对象，沿用未知字段、重复JSON key（经 `io.load` 的 object_pairs_hook）、非有限值、bool充当整数、非法标识符（`[A-Za-z0-9_:-]{1,64}`）的拒绝约定；任何错误都以 ValueError 拒绝整份输入，不返回部分布局或部分重定位。

- regions 1..16 项 `{name,base,size}`：name 唯一，base 整数 0..1000000，size 整数 1..100000，半开区间不得重叠（端点相接允许）。
- objects 1..32 项 `{id,sections,symbols,relocations}`：id 全局唯一；全部对象合计至多 100 section、1000 symbol、2000 relocation。
- section `{name,region,size,alignment}`：name 对象内唯一，region 必须存在，size 1..100000，alignment 为 1..4096 的二次幂；section 不携带基址。
- symbol `{name,section,offset,binding}`：name 对象内唯一，section 属于本对象，offset 满足 `0<=offset<size`；binding 仅 `local/weak/strong`，local 仅对象内可见，weak/strong 导出为全局候选。
- relocation `{id,section,offset,symbol:{scope,name},addend,width}`：id 对象内唯一，section 属于本对象，scope 仅 `local/global`，addend 整数 ±1000000，width 1..8；写区间 `[offset,offset+width)` 必须完全落在 section 内，同对象同 section 的写入不得重叠。

布局与输入数组排列无关：每个 region 内按 `(object.id, section.name)` 字典序放置，从 region.base 起把起始地址向上对齐到 section.alignment 再推进 size；任一 section 越过 region 末端即整体失败。region 的输入排列不影响结果。

全局解析：每个全局名称至多一个 strong；存在 strong 时它胜出、其余 weak 记为 shadowed；没有 strong 时在同名 weak 中取 object.id 字典序最小者，其余为 shadowed（按 object.id 排序）。多个 strong、引用无可见定义（local 引用只查本对象，global 引用不把 local 当候选）均拒绝。重定位值为目标绝对地址加 addend，必须满足 `0<=value<2^(8*width)`，负值不截断、不按补码编码，输出小端字节数组。

成功结果：`sections` 按 `(region,object,section)` 排序给出 object/name/region/base/size/alignment；`symbols.definitions` 给出全部定义的限定身份、绝对地址与 binding，`symbols.globals` 逐全局名称给出 winner 及 shadowed weak 候选；`relocations` 按 `(object,id)` 排序，含原始身份、解析目标限定身份、目标地址、value 与小端 bytes；`summary` 给出 regions/objects/sections/symbols/relocations 计数。仅重排任一输入数组时输出必须逐字节一致。`process` 的单对象输入、输出与拒绝边界保持不变。

## 部署重定位读回认证 `certify(data)`

独立于 `process`/`link` 的离线发布认证入口，同样不连接设备、不解析或执行ELF/PE/机器代码。输入是只含 `plan`、`collectors`、`targets`、`captures`、`requests` 的JSON对象，沿用未知字段、bool充当整数、非法标识符、重复身份的拒绝约定；任何错误（包括 `link(plan)` 失败）都以 ValueError 拒绝整份输入，不返回部分 request 或 certificate。

- `plan`：现有 `link` 可接受的完整输入；认证前按现有契约得到确定的 section 布局与每条 relocation 的最终 bytes。认证对象是这些 relocation 写入区间，不推断未被 relocation 覆盖的普通 section 内容。
- `collectors` 1..64 项 `{id,group,valid_from,valid_to}`：id 唯一，group 为信任域身份（同组不算独立信任域），时间为 0..1000000000 的整数，区间 `[valid_from,valid_to)` 必须非空。
- `targets` 1..32 项 `{id}`：id 唯一。每个目标部署同一份 `plan` 结果，地址不再二次平移。
- `captures` 0..20000 项 `{id,target,collector,observed_at,ranges}`：id 全局唯一；target/collector 必须存在；observed_at 必须落在该 collector 有效期内；同一 `(target,collector,observed_at)` 不得重复。ranges 0..128 项 `{base,bytes}`，bytes 为 1..4096 个 0..255 整数；单份 capture 内区间（半开）不得重叠，每个区间必须完全位于某个 plan region 内且不得跨 region；全部 capture bytes 合计至多 4000000。
- `requests` 1..2000 项 `{id,target,as_of,min_collectors,min_groups}`：id 唯一；target 必须存在；as_of 为 0..1000000000 整数；两个门槛均为正整数且 `min_groups<=min_collectors<=64`。

证据选取：对每个 request，仅使用 `observed_at<=as_of` 且 collector 在 as_of 时仍有效（`valid_from<=as_of<valid_to`）的 capture；每个 `(target,collector)` 只取截至 as_of 的最新 capture，较早 capture 即使更完整也不得为最新 capture 补字节。最新 capture 可用自身多个 ranges 拼成一个 relocation 的完整读回，不得与该 collector 旧 capture、其他 collector 或其他 target 混拼。输入数组顺序不影响最新版本选择与结果。

逐 relocation 判定（写入地址=section base+offset，期望字节来自 `link(plan)`）：某最新 capture 覆盖全部字节且逐字节相同为 `match`；只覆盖一部分且所见字节均相同为 `incomplete`；覆盖到的任一字节不同为 `mismatch`；完全没有读回覆盖也是 `incomplete`。任一有效最新 capture 出现 mismatch 时该 relocation 不得认证：同时存在 match 与 mismatch 为 `conflict`，只有 mismatch 为 `mismatch`；没有 mismatch 时 match collector 数达到 min_collectors 且其不同 group 数达到 min_groups 才 `certified`，否则 `insufficient`。

request 只有在 plan 至少含一条 relocation 且每条 relocation 都 `certified` 时才是 `certified`；零 relocation 的 plan 返回 `no_relocations`，不签发空认证；否则 request 状态为各未通过 relocation 中严重度最高者（`conflict`>`mismatch`>`insufficient`），且不产生部分 certificate。

成功结果：`plan` 含现有 link summary 与按 `(object,id)` 排序的预期 relocation 身份（object/id/section/offset/width）、实际写入地址 address 与 expected bytes；`requests` 按 request id 排序，每项给出 target/as_of/门槛/最终 status，逐 relocation 列出 match、incomplete、mismatch 的 collector/group/capture/observed_at 身份与实际观察到的相关字节（未覆盖位为 null），以及门槛判断（min_collectors/min_groups/match_collectors/match_groups/met），冲突可追溯到具体 capture。对 `certified` 项给出 `certificate`：request/target/as_of、门槛、完整预期 relocation 身份，以及每条 relocation 的 witness——match collector 先按 `(group,collector)` 排序取到 min_groups 个不同 group，再按同一顺序补足 min_collectors，多余 match、incomplete 与无关 capture 不写入证书。`certificate_id` 是 certificate 正文（不含 certificate_id）按 UTF-8、`ensure_ascii=True`、键排序、紧凑分隔符 `(',',':')` 序列化后的 SHA-256 十六进制；诊断列表、未选 witness 与输入排列不影响 certificate_id。`summary` 给出 requests 各状态计数、certified 数与总数。仅重排 collectors、targets、captures、requests、ranges 或 plan 中现有可重排数组时，语义结果与 certificate_id 必须相同。

## 目标计划升级影响评估 `assess_upgrade(data)`

独立于 `process`/`link`/`certify` 的离线升级影响评估入口，不连接设备、不执行目标代码、不读取读回 capture，也不签发部署认证。输入是只含 `current`、`candidate`、`consumers` 的 JSON 对象，沿用未知字段、bool 充当整数、非法标识符、重复身份与引用错误的拒绝约定；任何输入错误或任一侧 `link` 失败都以 `ValueError` 拒绝整份输入，不返回部分评估。

- `current`、`candidate` 各自都是现有 `link` 可接受的完整输入，代表同一目标地址空间中替换前后的完整计划。API 分别独立调用 `link(current)` 与 `link(candidate)`，不把一侧的布局、符号胜出结果或索引带入另一侧。
- `consumers` 1..256 项 `{id,objects,binding_policy}`：`id` 唯一且为合法标识符；`objects` 为 1..32 个不重复的目标对象 id；`binding_policy` 只能是 `address` 或 `provider`。一个对象 id 最多归属一个 consumer。每个对象引用都必须至少出现在 current 或 candidate 一侧；consumer 也因此至少有一个可评估对象。

对象存在性以两份已验证计划的对象 id 表为准（允许对象没有 section 或 relocation）。若一个 consumer 同时含有仅 current 存在和仅 candidate 存在的对象，整份输入拒绝；不得把这种混合迁移折算成新增、删除或继续运行。

relocation 的比较身份为 `(object,id)`，明细按该身份排序。每侧绑定事实包含现有 `link` relocation 行中的 `section`、`offset`、`width`、`target:{object,name}`、目标符号 `address`、`value`、`bytes`，并补充由 link sections 推出的实际写入地址 `write_address=section.base+offset`。每条明细为：

```json
{
  "object": "o1",
  "id": "r1",
  "status": "unchanged | changed | added | removed",
  "current": {"...": "current 侧完整绑定事实；added 时为 null"},
  "candidate": {"...": "candidate 侧完整绑定事实；removed 时为 null"},
  "changed_fields": ["发生变化的顶层绑定字段"],
  "field_differences": {"field": {"current": null, "candidate": null}}
}
```

`added`/`removed` 由比较身份是否只在一侧存在决定；两侧都有但任一绑定事实不同为 `changed`，否则为 `unchanged`。`changed_fields` 按 `section,offset,width,target,address,write_address,value,bytes` 的固定比较顺序输出；`field_differences` 保留两侧值以便复核。

每个 consumer 输出按 id 排序的 `{id,objects,binding_policy,action,relocations}`，其中 `objects` 也按 id 字典序排序。唯一动作按下列规则从明细推出：

- `keep_running`：consumer 在两份计划均存在，没有 added/removed relocation 身份，且每条共同 relocation 的 `write_address` 与 `bytes` 不变；`provider` 契约还要求 `target` 限定身份不变。无 relocation consumer 在两份计划均存在时为此动作。
- `rebind_required`：consumer 在两份计划均存在，但有 relocation 身份增删、`write_address` 或最终 `bytes` 改变；`provider` 契约下 `target.object`/`target.name` 改变也必须重绑定。`address` 契约允许 target 提供者限定身份变化，只要写入地址与 bytes 不变。
- `activate_new`：consumer 的全部对象仅在 candidate 存在；明细列出 candidate 侧 added relocation。
- `stop_removed`：consumer 的全部对象仅在 current 存在；明细列出 current 侧 removed relocation。
- 部分对象在两侧、部分仅在一侧且没有混合两类独占对象时，consumer 仍按两侧均存在处理；仅一侧对象带来的 added/removed relocation 会一致地推出 `rebind_required`，无 relocation 变化时才可 `keep_running`。

只改变 `binding_policy` 不改变计划或比较明细，但动作必须按新契约重新计算。成功结果的 `current`、`candidate` 字段分别是 `link` 返回的 `summary`；`summary` 同时扁平给出四个动作计数、在 `actions` 中给出同一组计数，并给出 `consumers` 总数（以及与既有 API 命名一致的 `total` 同义字段）。混合新增与删除不产生第五种成功动作，而是按上述规则整份拒绝。consumer/object 数组及两份计划中现有可重排数组的排列均不影响输出。`process(data)`、`link(data)`、`certify(data)` 的输入、输出和拒绝边界保持不变。

## 目标内存差分发布包 `build_release_bundle(data)`

独立于前四个入口的离线差分发布 API，不连接设备、不实际写内存，也不解析或执行 ELF/PE/机器码、不提供 CLI。输入只含 `releases`、`targets`、`receipts`；未知字段、bool 整数、非法字节/ID、重复身份、非法引用或任一 release 的 `link(plan)` 失败，都按既有 `ValueError` 边界拒绝整份输入。

- `releases` 1..32 项 `{id,plan,images}`：`plan` 是完整 `link` 输入；`images` 必须按 `(object,section)` 为每个链接 section 恰好提供长度等于 `size` 的 0..255 数组。先应用原始 image，再把 `link` relocation 的最终小端 bytes 覆盖到对应偏移，得到最终绝对地址映射。全部 image bytes 至多 4,000,000。
- `targets` 1..64 项 `{id,current,candidate,erase_byte,atomic_ranges,max_batch_bytes}`：current/candidate 必须引用 release，允许相同。atomic range 为目标内唯一 `{id,base,size}`，size 1..65536，半开区间不得重叠，且每个地址必须同时被 current/candidate section 覆盖。
- `receipts` 0..10000 项 `{id,target,bundle_id,observed_at,acked_chunks}`：id 全局唯一，target 必须存在，时间 0..1e9，`(target,bundle_id,observed_at)` 唯一；acked chunk id 为不重复的小写 SHA-256 十六进制字符串。

比较两侧最终绝对地址映射：candidate 覆盖地址以 candidate 为期望；仅 current 覆盖地址以目标 `erase_byte` 为期望；仅 candidate 覆盖地址的回滚值也是 `erase_byte`；两侧均不覆盖的地址不属于发布范围。对象/section 身份变化但最终地址字节相同不产生写入。非 atomic 变化按绝对地址合并为最大连续变化区间；atomic range 中任一字节变化时，整个 range 成为一个 base/size 不变、不可拆分的单元，前向取 candidate 完整 range，回滚取 current 完整 range。无变化 atomic range 不产生单元，但其 `{id,base,size}` 属于规范化 target 契约，边界变化会改变 `bundle_id`。

单元位于 target 的 `forward`/`rollback` manifest（同时提供 `forward_manifest`/`rollback_manifest` 别名），按 base 排序，每项为 `{base,size,atomic_range,chunk_id}`；普通区间的 `atomic_range` 为 `null`。payload 是 bytes 数组，其 `chunk_id` 为 `json.dumps(bytes, ensure_ascii=True, separators=(',',':'))` 的 SHA-256 十六进制。全 bundle 的 `chunks` 按 id 排序并去重为 `{chunk_id,bytes,size}`；地址、方向和 target 不参与 chunk id。任一 manifest chunk 大于引用目标的 `max_batch_bytes` 即整份拒绝。

规范 bundle 正文包含排序后的 release 摘要/地址范围/字节数、去重 chunks，以及排序后 target 的 current/candidate/erase_byte/atomic ranges 和完整 forward/rollback manifest；不含 receipt 选择、pending batch 或 `bundle_id`。正文以 `ensure_ascii=True`、`sort_keys=True`、紧凑分隔符序列化后的 SHA-256 为 `bundle_id`，输入数组重排不改变该 id。

仅选择 target 下 `bundle_id` 相同且 `observed_at` 最大的 receipt 做续传；同一 bundle 的任一 receipt 引用非该 target manifest chunk 均拒绝整份输入，其他 bundle_id 的旧 receipt 不抵扣也不校验当前 chunk。输出 target 还给出选中 receipt id（`receipt_id`/`selected_receipt` 等别名）、排序后的 `acknowledged_chunks`、`pending_chunks` 与贪心顺序批次 `pending_batches`。批次按 chunk_id 字典序装包，单 chunk 不拆分，总 `bytes` 不超过 `max_batch_bytes`，放不下即开下一批。空 forward manifest 为 `up_to_date`；有写入且无 pending chunk 为 `ready`；否则为 `transfer_pending`。`summary` 含 `releases,targets,chunks,forward_units,rollback_units,payload_bytes,pending_targets,up_to_date_targets`。

## 发布执行日志对账与一致性恢复 `reconcile_rollout(data)`

独立于前五个入口的离线路径恢复 API，供离线发布控制器在目标代理重启、重复上报或跨目标切换中断后重建各目标已持久化的发布状态，并决定同一一致性组的下一步。它不连接设备、不实际写内存、不伪造执行成功、不新增 CLI，也不改变 `process`/`link`/`certify`/`assess_upgrade`/`build_release_bundle` 的输入、输出与拒绝边界。输入只含 `bundle`、`groups`、`journals`；未知字段、bool 充当整数、重复身份、非法引用、容量超限、日志链错误、非法状态转换或 `build_release_bundle(bundle)` 失败，都以 `ValueError` 拒绝整份输入，不返回部分对账结果。

- `bundle` 是现有 `build_release_bundle` 可接受的完整输入。对账前必须先调用该 API，得到本次规范 `bundle_id` 与各 target 的完整 forward/rollback manifest；日志只证明目标代理已持久化的执行事实，不得改变 bundle、chunk、manifest 或 `bundle_id`。
- `groups` 1..32 项 `{id,targets,policy}`：id 唯一；targets 为 1..32 个不重复的 bundle target id，每个 target 必须且只能属于一个 group，且所有 bundle targets 都必须被覆盖；policy 仅 `atomic` 或 `independent`。`atomic` 表示组内共享一个不可逆提交点：任一目标持久化 commit 后其余目标不能回到旧版本；`independent` 允许各目标按自身日志单独完成或回滚。
- `journals` 0..20000 项 `{id,target,bundle_id,attempt,previous,events}`：id 全局唯一；target 必须存在；`bundle_id` 为字符串；attempt 为 1..1000000000 整数；同一 `(target,bundle_id,attempt)` 只能一项。previous 为 null 或同一 target、同一 bundle_id、较小 attempt 的 journal id。events 0..4096 项 `{seq,type,unit}`，seq 从 1 起连续递增；type 仅 `forward_applied`/`commit`/`rollback_applied`/`rollback_complete`；applied 事件的 unit 是对应 manifest 单元的 `{base,atomic_range}` 身份，commit/rollback_complete 的 unit 必须为 null。全部 events 合计至多 200000。

日志选择与链重建：只选择本次计算出的 bundle_id 的日志；其他 bundle_id 的日志作为旧历史忽略，既不提供当前进度，也不要求其中 unit 存在于当前 manifest。对每个 target，从当前 bundle_id 下 attempt 最大的 journal 开始沿 previous 反向取链；链必须终止于 previous=null，不得成环、断链、跨 target/bundle 或跳到不小于当前 attempt。未被最新链引用的较早分支是被放弃尝试，其进度不得与最新链拼接，只在输出中列为 `abandoned_journals`。链内按 attempt 升序、段内 seq 升序重放，输入数组排列不影响选择与结果。

重放按完整 manifest 校验，而非只看事件名称：

- `forward_applied` 只能引用该 target forward manifest 中尚未成功应用的单元；同一有效链内重复上报同一单元是幂等重放，不重复计数。`commit` 只有在全部 forward 单元都已应用后才合法；空 forward manifest 的 target 视为初始即完成前向，但仍需显式 commit 才跨过提交点。commit 最多一次，提交后不得再出现 forward_applied。
- `rollback_applied` 只能引用 rollback manifest 单元；提交前只允许回滚已前向应用单元对应 base 的 rollback 单元，尚未前向应用的单元不得伪造回滚；commit 后禁止任何 rollback 事件。`rollback_complete` 只有在所有已前向应用单元都已回滚后才合法，完成后不得再出现其他事件。
- forward 与 rollback manifest 按 base 一一对应。日志 `{base,atomic_range}` 必须与目标 manifest 精确匹配：不能只用 base 猜测 atomic 身份，也不能引用别的 target，即使 chunk 相同。base 存在但 atomic_range 冲突按身份冲突拒绝。

目标重建状态为 `clean`（无当前 bundle 有效事件，或 rollback_complete 后已回到旧版本）、`forward_partial`、`forward_complete`、`committed`、`rollback_partial`。输出同时给出历史已前向应用 `applied`、已回滚 `rolled_back`、当前仍需前向 `pending_forward` 与仍需回滚 `pending_rollback`；rollback_complete 后历史明细保留，但当前已应用集合为空、`pending_forward` 恢复为完整 manifest。某个 journal 的完整有效链是审计边界，被放弃分支不得补齐进度；全局 chunk 去重不允许跨目标共享执行进度。

组级恢复决定约束目标级命令：

- `independent` 逐目标判断：committed 或 clean 为 `hold`；forward_complete 为 `commit`；forward_partial 为 `continue_forward`；rollback_partial 为 `continue_rollback`。全部 hold 时组 decision 为 `stable`，否则为 `independent_recovery`。
- `atomic` 任一目标 committed 时组 decision 为 `finish_forward`：committed 目标 hold，forward_complete 目标 commit，clean/forward_partial 目标 continue_forward；此时组内存在任何 rollback 状态即与不可逆提交点冲突，整份输入拒绝。
- `atomic` 尚无 committed 时，任一目标 rollback_partial，或任一目标有前向进度而另一目标 clean，decision 为 `restore_old`：所有非 clean 目标 continue_rollback（尚未开始回滚时也从其已应用集合生成完整待回滚清单），clean 目标 hold。
- `atomic` 尚无 committed 且全部 forward_complete 时 decision 为 `commit_all`，每目标命令为 commit（计划命令不代表已执行，调用方需再次对账确认）；全部 clean 为 `stable`；其余无非 clean 以外状态且非 clean 目标均为 forward_partial（或仅含 forward_complete 与 forward_partial 的混合）时 decision 为 `finish_forward`，各目标继续自身剩余前向或先完成 commit。

每条命令含 `action`、`reason` 与精确 `units`：continue_forward 给出尚未应用的 forward 单元；continue_rollback 给出已前向应用但尚未回滚的 rollback 单元，按 rollback manifest 的 base 降序输出；commit 与 hold 的 units 为空。成功结果含：`bundle`（本次 `bundle_id` 与 build_release_bundle summary）；`targets`（按 target id 排序，给出所属 group、选中 journal/attempt 或 null、有效链 journal ids、被放弃的当前 bundle journal ids、state、committed、applied/rolled_back 与 pending_forward/pending_rollback；单元身份含 base、size、atomic_range、chunk_id）；`groups`（按 group id 排序，给出 policy、decision 与按 target id 排序的 commands）；`summary`（groups、targets、各 state 数量与 stable/finish_forward/commit_all/restore_old/independent_recovery 决定计数）。仅重排 groups、targets、journals、events 或既有 bundle 可重排数组时，结果必须相同；events 数组打乱但 seq 连续时按 seq 重建。
