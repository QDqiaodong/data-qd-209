# data-qd-209 · 目标文件符号重定位

按section基址、symbol偏移和addend计算固定宽度重定位字节，拒绝越界和溢出。

本仓主要交付是Python业务API和可供下游使用的结构化数据，不是通用CLI、报表或CRUD模板。字段、身份、单位、上限与失败边界见 [数据契约](docs/contract.md)。

## 安装与验证

Python >=3.11，实测CPython3.12.14、uv0.12.19。运行依赖仅标准库，构建固定setuptools80.9.0、wheel0.45.1；每仓独立 `.venv`。

```sh
uv venv --offline --python 3.12 .venv
uv pip install --offline --python .venv/bin/python -r requirements-build.lock
uv pip install --offline --python .venv/bin/python --no-build-isolation --no-deps .
uv pip check --python .venv/bin/python
.venv/bin/python -I -m unittest discover -s tests -v
.venv/bin/python -I examples/run_sample.py
```

上述命令已在本地缓存和独立环境真实执行；样例输出写入 `run/sample.json`，已有目标拒绝覆盖。API可这样调用：

```python
from obj_reloc import process
from obj_reloc.io import load, publish
publish("run/another.json", process(load("fixtures/input.json")))
```

样例摘要：

```json
{"relocations": 1, "sections": 2, "symbols": 2}
```

## 多对象链接 `link`

`obj_reloc.link` 是与 `process` 并列的独立入口，接收只含 `regions`、`objects` 的结构化 JSON，完成确定性内存布局、跨对象 strong/weak 符号解析与小端重定位编码；同样是离线数据 API，不解析或执行 ELF/PE/机器码，也不提供 CLI。任何输入错误都按既有 ValueError 约定拒绝整份输入，不返回部分结果。

```python
from obj_reloc import link
result = link({"regions": [...], "objects": [...]})
```

字段范围、解析规则、排序保证与输出结构见 [数据契约](docs/contract.md) 的“多对象链接”小节；`process` 的单对象契约保持不变。

## 部署重定位读回认证 `certify`

`obj_reloc.certify` 是与 `process`/`link` 并列的独立入口，接收只含 `plan`、`collectors`、`targets`、`captures`、`requests` 的结构化 JSON。链接结果写入目标内存后，它核对各采集方在不同时刻的地址区间读回，判断每次发布请求是否已有足够独立、仍受信任且彼此不冲突的证据，确认所有计划重定位字节确实落在目标地址；同样是离线数据 API，不连接设备、不解析或执行 ELF/PE/机器码，也不提供 CLI。任何输入错误都按既有 ValueError 约定拒绝整份输入，不返回部分 request 或 certificate。

```python
from obj_reloc import certify
result = certify({"plan": {...}, "collectors": [...], "targets": [...],
                  "captures": [...], "requests": [...]})
```

最新 capture 选取、逐 relocation 判定、witness 选择、`certificate_id` 规范形与输出结构见 [数据契约](docs/contract.md) 的“部署重定位读回认证”小节；`process` 与 `link` 的既有契约保持不变。

## 目标计划升级影响评估 `assess_upgrade`

`obj_reloc.assess_upgrade` 是与前三个入口并列的独立离线评估 API，接收只含 `current`、`candidate`、`consumers` 的 JSON 对象。两份计划分别独立调用 `link`，再按消费者的 `address`/`provider` 契约比较 `(object,id)` relocation 绑定，输出 `keep_running`、`rebind_required`、`activate_new`、`stop_removed` 四种动作及计数；混合新增/删除对象、未知引用、重复归属或任一侧链接失败均拒绝整份输入。它不连接设备、不执行目标代码、不读取 capture，也不签发认证。

```python
from obj_reloc import assess_upgrade
result = assess_upgrade({"current": {...}, "candidate": {...},
                         "consumers": [...]})
```

比较明细、写入地址口径、排序与拒绝边界见 [数据契约](docs/contract.md) 的“目标计划升级影响评估”小节。

## 目标内存差分发布包 `build_release_bundle`

`obj_reloc.build_release_bundle` 是新的独立离线发布控制器 API，接收只含 `releases`、`targets`、`receipts` 的 JSON 对象。它把原始 section image 与 `link(plan)` relocation 覆盖合成为最终绝对地址映射，跨 current/candidate 比较字节，生成支持 atomic range 和精确 rollback 的 chunk/manifest；相同 payload 跨地址、方向和目标去重。历史回执只选择匹配当前 `bundle_id` 的最新一份来生成 `pending_batches`，从而支持传输中断后续传。它不连接设备、不实际写内存、不解析或执行 ELF/PE/机器码，也不新增 CLI。

```python
from obj_reloc import build_release_bundle
bundle = build_release_bundle({"releases": [...], "targets": [...], "receipts": [...]})
```

image/relocation 合成、atomic 单元、chunk 规范化、`bundle_id`、回执选择、批次装箱和拒绝边界见 [数据契约](docs/contract.md) 的“目标内存差分发布包”小节。

## 发布执行日志对账与一致性恢复 `reconcile_rollout`

`obj_reloc.reconcile_rollout` 是与前五个入口并列的独立离线恢复 API，接收只含 `bundle`、`groups`、`journals` 的 JSON 对象。它先调用 `build_release_bundle(bundle)` 得到本次规范 `bundle_id` 与各 target 的完整 forward/rollback manifest，再沿每个 target 当前 bundle_id 下最大 attempt 的 previous 链（跨重启 attempt 续接，被放弃分支不拼接）按 seq 重放追加日志，重建 `clean`/`forward_partial`/`forward_complete`/`committed`/`rollback_partial` 状态，并按 `atomic`/`independent` 组策略给出 `stable`、`finish_forward`、`commit_all`、`restore_old`、`independent_recovery` 决定与逐目标 `hold`/`commit`/`continue_forward`/`continue_rollback` 精确命令。日志只证明已持久化事实，不改变 bundle；非法链、未知/冲突单元、过早 commit/rollback_complete、commit 后回滚冲突等一律 `ValueError` 拒绝整份输入。它不连接设备、不实际写内存、不伪造执行成功，也不新增 CLI。

```python
from obj_reloc import reconcile_rollout
result = reconcile_rollout({"bundle": {...}, "groups": [...],
                            "journals": [...]})
```

日志选择、链重建、状态机校验、组级决定、命令单元排序与输出结构见 [数据契约](docs/contract.md) 的“发布执行日志对账与一致性恢复”小节；前五个 API 的既有契约保持不变。

已通过 75 项业务测试（原有 59 项与新增差分发布包测试），并核对非法输入拒绝；样例数据全部原创合成，见 [来源](fixtures/SOURCES.md)。

## 边界

业务结果仅覆盖契约中定义的有限模型。后续需求可沿已有身份和证据字段扩展，不把当前样例当成行业标准或生产认证。
