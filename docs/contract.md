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
