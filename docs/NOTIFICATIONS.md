# 序号通知与写入结果查询

通知只缩短客户端发现变更的等待时间。账号、权限、密文、恢复状态和接受序号仍以单个账号的 SQLite 事务为权威；通知没有写入或授权能力。断线、重复提示或通知丢失都不能改变权威状态。

## 单次连接票据

已完成设备持钥验证的客户端使用正常设备绑定会话，请求 `POST /v1/accounts/{accountId}/notification-tickets`，JSON 必须为空对象 `{}`。请求头为 `Authorization: Bearer <device-session-token>`、`X-Harmonia-Device-Id` 和 `X-Harmonia-Account-Generation`。

成功返回 `{ticket,expiresAt,sequence}`。票据随机 32 字节，最长 30 秒，同时不超过当前会话与可读授权的期限。服务器只持久保存票据 SHA256、原会话哈希、设备及账号代际；每个账号最多 32 张待用票据，每个设备最多 4 张，过期清理。密码登录产生的未绑定会话、恢复会话、已撤销设备或没有任何当前可读环境的设备不能申请。

随后以同样设备/代际请求头和 `Authorization: Bearer <ticket>`，执行 `GET /v1/accounts/{accountId}/notifications` 的 WebSocket Upgrade。URL 不得带任何 query，包括票据和会话 token。票据在账号权威事务内原子单次消费；错误账号、设备、代际、过期或重复使用均拒绝。消费时再次检查原会话与当前授权。握手失败导致结果不明时重新申请票据，不能重复消费旧票据。

该握手面向可设置请求头的 Go 与原生 Flutter 客户端。浏览器原生 WebSocket API 不能设置这些认证头，当前没有浏览器连接方案。代理、访问日志、错误收集与监控不得记录 Authorization 或请求正文；Workers 自动观测默认关闭，启用前须完成脱敏验收。

## 消息与权限边界

服务端发送 JSON `{accountId,accountGeneration,sequence}`。没有环境 ID、名称、变量名、值、密文、封套、恢复码或凭据。客户端不得把提示当已验证数据或推进已应用检查点，只按正常 HTTPS 拉取路径取得持久事件并验证签名、授权、版本与已见检查点。

握手后，连接只保存账号/代际/设备及原会话哈希等元数据，不复制权限或密码验证状态。每次发送前立即重读同一账号权威状态，验证设备非撤销、设备绑定会话有效和至少一个当前可读环境。检查到发送之间没有异步等待，不能只相信握手时的授权。失效时发送固定关闭码 `4003`，原因是固定字符串，不含环境信息。客户端必须刷新授权或尝试受信设备 boot 续期，并根据确定的撤销/代际失效清理托管来源；本地签名授权到期也须离线执行，不能等待网络关闭事件。

Node 在事务真正 COMMIT 后观察变更，发送失败不改变已提交结果。Node 用到期 timer 主动关闭。Workers 在每账号 DO 内观察同一提交，使用官方休眠 WebSocket API 与连接 attachment；存储 alarm 在最近会话/授权到期时唤醒并重查。D1 没有票据、连接权限或序号的副本。每个运行实例/账号 DO 最多 256 个连接，每设备最多 4 个；Node 关闭慢连接并提示重新连接。WebSocket 不能提交业务消息；客户端应用消息会被关闭，业务写入仍须 HTTPS 签名入口。

账号序号包含该账号其他环境的接受操作，因此提示序号可以跳跃；它没有针对某设备连续事件流的承诺。连接建立时提示当前持久序号。重连以后仍须从本地数据检查点拉取补漏；新增授权或钥匙版本变化按既有规则全量补拉。暂停期间使用独立授权投影与授权检查点，不能把提示当作继续同步变量的指令。没有通知时保留定期拉取作为补漏机制。

## 本人写入收据

`GET /v1/accounts/{accountId}/mutation-status?idempotencyKey={id}` 只接受一个幂等键 query，使用正常设备绑定会话。它重查当前账号代际、会话与设备非撤销状态，仅查询 `mutation/{current-device}/{id}`。其他设备的相同 ID 不会暴露本人结果。

未接受返回 `{idempotencyKey,accepted:false}`。已接受返回 `{idempotencyKey,accepted:true,sequence,contentHash}`；`contentHash` 为小写十六进制 SHA256，输入是原始幂等记录字符串，即 `base64url(canonicalMutation)+"."+signature` 的 UTF-8 字节。响应不含变量名、值、密文、会话或原签包。

查询历史收据不要求该旧环境当前仍存在或可读，因为它没有下发环境数据或授予权限。仍受信的设备可在环境轮换、删除或环境授权撤回后核验丢失响应的旧写入；全局设备撤销、会话到期和旧账号代际拒绝。查询不修改接受序号，也不把旧包当新写。客户端须与本地持久日志中的固定原包 hash 比对；成功后仍经拉取流更新本机，不直接乐观应用。

## 实测与限制

合成 SQLite、真实 Node TCP/WebSocket 与实际本地 workerd 验证单次票据、跨账号/设备、未可信登录拒绝、撤销/期限/代际重查、仅序号消息、断线补漏、提交失败不通知、本人收据和大密文请求边界。测试不使用用户真实凭据或环境变量。

本地 workerd 的 alarm 按期限发送了实际 `4003` 关闭帧，客户端已收到并回送关闭帧；Miniflare 代理的 TCP FIN 曾延迟，标准 `close` 事件在五秒内未到达。回归明确校验固定成熟 ws Receiver 所解析的真实关闭帧，没有把代理最终 TCP 关闭当通过；线上休眠恢复、连接容量和 TCP 关闭行为仍待验收。任何通知或 alarm 延迟都不能绕过逐次业务检查和客户端本地到期执行。

运行时依据 [Cloudflare 休眠 WebSocket 文档](https://developers.cloudflare.com/durable-objects/best-practices/websockets/)、[alarm 文档](https://developers.cloudflare.com/durable-objects/api/alarms/) 与 [ws 官方文档](https://github.com/websockets/ws)。这些机制已本地测试，不构成生产安全验收。
