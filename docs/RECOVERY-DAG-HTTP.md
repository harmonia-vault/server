# 重复恢复的 major2 业务入口

本说明补充已定义的恢复 DAG 与证书5密码学合同；不改变原语或签域。该业务入口使用 HTTPS，并明确请求与响应 `Harmonia-Protocol-Major: 2`。`GET /protocol-info` 返回支持的 major 和各 major 的能力；新流程必须具备 `issuer-recovery-dag-v1`，不回退到旧来源 parser。

账号级路由位于 `/v1/accounts/{accountId}`：

| 路由 | 方法 | 作用 |
| --- | --- | --- |
| `/recovery-vault-v2?capability=issuer-recovery-dag-v1` | GET | 当前公钥、受限状态、恢复封套、原初始化及完整已接受来源 |
| `/recovery-authority-challenges-v2?capability=issuer-recovery-dag-v1` | POST | 冻结当前代际、序号、恢复头、完整环境清单和一次 nonce |
| `/recovery-authority-transitions-v2?capability=issuer-recovery-dag-v1` | POST | 提交 `RecoveryTransitionCommandV2` |
| `/recovery-authority-transitions-v2/{operationId}?capability=issuer-recovery-dag-v1` | GET | 仅查询原 ID、接受序号和原签包 hash |
| `/recovered-device-challenges-v2?capability=issuer-recovery-dag-v1` | POST | 当前受限会话明确选择新的设备双公钥 |
| `/recovered-devices-v2?capability=issuer-recovery-dag-v1` | POST | 提交 `RecoveredDeviceCommandV2` 的恢复签名与 HPKE 后设备反签 |
| `/recovered-devices-v2/{operationId}?capability=issuer-recovery-dag-v1` | GET | 查询不可变的原接受收据 |
| `/pairings-v5` 及其 status/relay/approve/complete 子路由 | GET/POST | 原生 PAKE 与证书5双签入网 |

共用的邮件、登录、恢复挑战和设备 Boot 路由仍按原精确 wire 运作。P4 Pull 使用 `capability=issuer-recovery-dag-v1`；签变量写入和幂等收据保持原域，不能把来源验证当作当前写权限。

服务端在唯一账号事务内重验账号代际、当前角色与期限、恢复代际和头、冻结序号、单次 nonce、完整环境版本与封套。只有新恢复公钥、所有必要封套及已接受历史一起提交成功，旧恢复码才失效。同 ID 与同不可变签包只返回原接受序号；不同内容、跨种类 ID 或过期的未接受 nonce 不产生新写入。网络结果未知时只查询原 ID，客户端不能偷偷取新 nonce、重签或换码。

新设备登记仍使用受限会话。明确角色和期限、完整来源图、恢复签名以及设备 HPKE 反签通过后只产生接受记录；设备还须持本机签名钥 Boot，按相同来源验证 Pull，再成功保存本机保护状态。登录成功或服务器公钥目录不是设备可信凭证。

账户安全权威仅存账号事务状态；D1 保持目录职责。原初始化或已接受来源历史缺失的旧状态不能从目录重建 pin。账号已进入 DAG 状态后，旧恢复和旧入网路由拒绝绕过；旧 parser 不能吞 P4。

这是实验性接口。当前纵链实现连续恢复；P4 环境控制与 create/rotate 使用明确 major2 路由，rename/delete 保留原路由的 header 兼容并校验当前 DAG 权源，合同见 protocol 的 P4-ENVIRONMENTS.md；manager-reanchor 新入口、全局设备撤销及移动 UI 仍有后续接线门槛。Node/Workers 合成签包测试与 Go 真实 HPKE/原生 PAKE 联合测试需分别记录范围。


`GET /issuer-evidence?environmentId=E&capability=issuer-recovery-dag-v1` 返回 typed P4 和完整当前接收者集合；`POST /environment-changes-v4` 与原 ID status 共用 V2/V3 的环境签名包与幂等库。新 P4 create/rotate 逐次核当前完整 DAG 权源，旧 profile 不能绕过；同一已接受包的原收据仍跨路由稳定。rename/delete 沿原签名域，在已要求 DAG 的账号上也核当前 DAG 来源。没有把安全权威移到 D1 或另建冗余账号状态。

新增 Node TCP 与真实本地 workerd/SQLite DO 回归分别检查 CRUD、完整接收者轮换、角色与期限、缺接收者/旧快照拒绝、major/capability/禁 query，以及接受原包跨 DAG 与旧路由后的收据。该层封套和密文使用合成字节，不证明 HPKE 或 PAKE；它们由 workspace 的真实 Go HTTPS 联合主项单独记录。


## P4 每环境授权管理

`GET /grant-management?environmentId=E&capability=issuer-recovery-dag-v1` 要求 major2，返回原七字段 DTO，`issuerEvidence` 明确是 P4；包含精确已接受身份归档、各 subject 当前签包与最高 GG，target 仅为当前有效 actor Admin。进入 DAG 的账号不能使用旧 capability 获得旧投影。

`POST /grants`、`GET /grant-status?idempotencyKey=K` 保留原域、SignedGrant 与不可变收据。P4 客户端请求 major2；raw 旧路由保持 header 兼容，但 DAG 账号每次 POST 必须在同一账号事务内验证完整当前 DAG、目标双公钥归档、当前 Admin/KV/GG/期限与最高 GG+1，旧调用者不能绕过来源验证。nonce/恢复安全权威不另存 D1。相同 ID 同签包只返回原序号，不同签包冲突；失权后仍可用当前绑定 trusted 会话查询本人原收据。

none/过期/旧 KV 仍保留最高代际及冻结历史 Admin 来源，不能变成当前权限。null/GG0 不证明历史不存在；客户端保留已见下界。显式恢复旧 none 授权必须当前 KV、最高 GG+1、精确可信目标，并重新生成完整 HPKE 封套。

新增测试实际运行 Node TCP 和本地 workerd/SQLite DO，覆盖 RO/RW/Admin/none、期限上限与到期、代际/同 ID 冲突、缺身份归档和收据。该层封套为合成字节；真实 HPKE、原生 PAKE、原包密封重开及本机下发由 Go HTTPS 联合主项单独证明。
