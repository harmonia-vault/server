# 实例连接与注册策略

本切片接入真实 Node SQLite / Workers SQLite DO 业务，不是演示注册。当前仍为实验性实现；手机端连接、注册和首次可信初始化的联合用户流程另行验收。

## 公开连接合同

`GET /instance-info` 只接受 GET 与空 query，所有响应 `Cache-Control: no-store`。成功的完整 JSON 为：

```json
{
  "product": "harmonia",
  "status": "experimental",
  "protocol": {
    "supportedMajors": [1],
    "capabilities": ["registration-policy-v1", "email-proof-v1"]
  },
  "initialRegistrationAvailable": true,
  "allowRegistration": false,
  "emailVerificationRequired": true
}
```

三项注册字段为 boolean，不含账号数量、邮箱、账号 ID、凭据或证明。协议 major2 尚未开放；此接口也没有把 DAG 内核通过变成新路由支持。客户端应先验证标准 HTTPS、精确产品标识、可接受的 protocol major 与完整类型，再进入账号流程；任意 HTTP 200 或 `/health` 不能代替这些验证。

`initialRegistrationAvailable=true` 时默认显示注册；首次已经完成时默认登录。`allowRegistration=true` 可以显示注册链接；关闭后隐藏普通注册链接，服务端仍允许尚未完成首次注册的实例竞争首号。连接查询与提交可能发生状态变化，客户端必须处理真实提交的拒绝。

## 仅两个配置开关

Node 为 `HARMONIA_ALLOW_REGISTRATION` / `HARMONIA_REQUIRE_EMAIL_VERIFICATION`，Workers 为 `ALLOW_REGISTRATION` / `REQUIRE_EMAIL_VERIFICATION`。默认关闭普通注册且要求邮箱验证；没有额外 bootstrap token、邀请、短信或第三个注册开关。

| 普通注册 | 邮箱验证 | 新实例 | 首次完成后 |
| --- | --- | --- | --- |
| false | false | 注册时竞争唯一首号 | 拒绝新注册 |
| false | true | 不同邮箱可待验证，完成证明后竞争唯一首号 | 拒绝其他初始候选激活与新注册 |
| true | false | 普通账号注册并完成激活 | 继续允许普通注册 |
| true | true | 注册后完成冻结的邮箱要求再激活 | 继续允许注册与验证 |

每个新账号持久化 `verificationRequiredAtRegistration`，在注册开始时固定且不可修改。之后开启验证只影响新注册，不锁住先前未验证账号；旧数据库缺字段按 false 迁移。关闭验证不会把 `verified` 改成 true，也不能让原 true 的待验证账号免证明。登录、初始化和配对只看账号固定要求；已登记设备 boot 仍逐次检查当前信任/授权。

首次完成标记永久保留，重置、删除或清空账号不会重新开放首号。关闭注册的首次账号采用先到先得，请在本机先完成注册再公开实例地址。

## 待验证、首次决定和故障恢复

要求验证的注册先建立空待激活账号，再发送十五分钟单次邮件证明。不同邮箱不占用独占首号位置。账号权威先原子核验/消费证明并持久化 `proof-ready`，再向实例权威请求不可逆首次 CAS 决定，最后在本账号事务内激活。验证关闭时同样先持久可恢复材料，再竞争首次决定。

跨 Workers DO 不是分布式事务：采用耐久证明 → 唯一赢家决定 → 幂等激活，所有中断状态都可恢复。实例只存首次完成与赢家 opaque ID，邮箱、凭据、nonce、设备/授权、恢复状态仍各自仅在账号 DO；D1 仍只有 `email` / `account_id` 路由列。Node 使用同样业务与 SQLite 持久化。待激活账号不能登录、初始化、boot 或用 reset 绕过激活。

首次 CAS 或激活写失败后，原证明可在 `proof-ready` 状态重试原操作，或由正确密码登录在 Argon2 验证成功后补全。错误密码、旧账号代际/验证值不触发补全。完整激活后证明仍保持旧单次终态：再次提交返回 `email_proof_invalid`，丢响应时使用原正确凭据正常登录确证，不能据此重注册或重发新证明。

初始候选输家在关闭注册期间不能激活。管理员后来开启普通注册时，该已证明账号可用原正确密码登录补全，原账号 ID/代际/验证值/验证要求不变，实例赢家与首次标记不变；客户端不能提交一个 boolean 自行授权。原 open 候选按注册时已经获得的 open 许可完成验证，不因另一账号先完成首次而被锁住。

只有从未激活、无设备/环境/vault 且仍为 pending 的账号可在十五分钟期限后重新申请同邮箱。服务器保留其账号 ID，代际加一，清除旧证明和会话，替换新凭据并生成新 admission。原 true 的验证要求保持；旧证明立即失效。legacy、完整账号与 proof-ready 都不能按这个流程覆盖。

升级时 Node 从实际已有完整账号采用首次完成状态。Workers 分页读取 D1 路由候选，再问各账号 DO 是否确有完整/legacy 账号，幂等采用第一个有效结果；孤 D1 预留不算账号。迁移先完成，才允许并发新申请竞争。新增 `INSTANCES` 绑定与 `v2-instance-registration` SQLite DO 迁移只写入源码配置，本轮未在 Cloudflare 执行。

## 账号 DTO 与错误

`POST /v1/register` 为 `{email,credential}`，credential 是固定客户端 SHA256 小写 hex。成功返回原 `{accountId,accountGeneration,verificationRequired}`，不创建可信设备。邮件重发、验证与破坏性 reset 接口见 [邮箱说明](EMAIL.md)；reset 始终要求新的 reset 用途邮件证明，不因注册开关或验证开关豁免。

| HTTP / code | 处理 |
| --- | --- |
| 403 `registration_disabled` | 首次已完成/初始候选失败，或当前关闭注册；不要自动改邮箱/重签 |
| 401 `unauthorized` | 错误登录凭据或仍待证明；不证明账号已激活 |
| 403 `registration_pending` | 待激活账号尝试会话/初始化/reset 等受限操作 |
| 401 `email_proof_invalid` | 错用途、错误/到期/已消费证明；完成丢响应先正常登录确证 |
| 401 `generation_stale` | 旧代际证明或请求，停止重放旧包 |
| 409 `account_exists` | 完整/legacy/未到期/已证明账号不能覆盖 |
| 409 `account_changed` | 事务前后账号/代际/验证值变化，不能当成功 |
| 503 `email_verification_unavailable` / `email_delivery_failed` | 发送器缺失或发送失败，失败关闭，不免验证 |
| 503 `instance_unavailable` | Registry 绑定/权威不可用，不能把实例视为注册成功 |
| 400 `query_forbidden` / 405 `method_not_allowed` | 连接 DTO 请求形状不符 |

不将凭据、证明或 SMTP 调试信息写日志。SQLite/DO 账号仍限 1 MB，Argon2 参数没有降低。真实邮件投递、线上资源与完整手机/CLI 用户链没有由本批局部回归代替；准确结果见 [测试记录](TESTING.md)。
