# 邮箱验证与破坏性账号重置

邮箱用于登录账号与账号所有权证明，不做收信验证。本实现包含两个独立注册开关，不设邀请制。邮件发送器缺失或配置不完整时，要求验证的注册和新的邮件证明请求失败关闭。

## 注册开关

`HARMONIA_ALLOW_REGISTRATION` / Workers `ALLOW_REGISTRATION` 控制能否新注册。`HARMONIA_REQUIRE_EMAIL_VERIFICATION` / Workers `REQUIRE_EMAIL_VERIFICATION` 控制未验证邮箱能否登录、初始化可信手机。只接受字面值 `true` 启用注册、字面值 `false` 关闭验证；默认关闭注册并要求验证邮箱。

关闭验证不会把邮箱标记为已验证。之后开启验证时，未验证账号需要先完成邮件证明。关闭注册不影响已有账号请求验证或经邮件证明重置。

`POST /v1/register` JSON 为 `{email,credential}`。`credential` 仍是客户端固定 SHA256 的小写十六进制密码等价凭据；服务器独立随机盐 Argon2id（64 MiB、3 次、并行度 1）。响应为 `{accountId,accountGeneration,verificationRequired}`。新账号为空，不自动建立可信设备。要求验证时先持久化未验证账号并发送证明；发送失败返回受控错误，保留空账号但移除该次不可用证明，可重发验证邮件，不能直接使用 vault。

## 邮件证明

`POST /v1/email-verification/request` 与 `POST /v1/account-reset/request` 都接收 `{email}`。邮箱未知时响应 `{accepted:true}`，不向其他地址发送内容；相同用途的账号证明请求间隔至少 60 秒，最多八个未过期证明。这只是基础账号内限流，不能代替生产入口的资源和滥用控制，也不承诺所有响应时序隐藏账号存在性。

邮件正文提供 `{accountId,accountGeneration,challengeId,token}`，并说明用途与风险。请只在本人主动发起的客户端输入证明。令牌是随机 32 字节、规范无 padding base64url；服务器只持久化 SHA256，绑定账号代际、用途、当前密码验证值和 15 分钟期限。邮件内容、令牌、密码等价凭据与 SMTP 身份信息不得进入应用日志或监控。

验证使用 `POST /v1/accounts/{id}/email-verification/complete`，JSON 为 `{accountGeneration,challengeId,token}`。验证成功才将邮箱标记已验证；同用途证明原子消费。错用途、账号/代际、令牌、过期和已消费证明拒绝。验证邮箱仍不等于设备可信。

证明仅放在请求 JSON 中，不能放查询参数或公开链接。所有响应 `Cache-Control: no-store`；跨设备/远程访问要求 HTTPS。

## 重置与断网结果查询

账号重置永久删除旧 vault，不恢复旧数据。用户必须明确确认：

```text
POST /v1/accounts/{id}/account-reset/complete
{accountGeneration,challengeId,token,newCredential,
 confirmation:"DELETE_OLD_VAULT"}
```

`newCredential` 使用同样的客户端 SHA256。服务器先验证当前邮件证明，在 SQLite/DO 事务外计算新 Argon2id，再在唯一账号权威事务内重新检查旧账号代际、密码验证值、证明哈希和期限。

成功时账号 ID/邮箱目录保持一致，账号代际加一、邮箱已验证，账号数据从全新空状态替换。旧设备、公钥、会话、环境、变量事件、授权/历史、幂等记录、恢复码公钥/封套、可信根、所有旧挑战和未来扩展字段全部清除；重新初始化新 vault。旧代际请求立即拒绝，旧密码不再登录。删除发生在同一个事务中，SQL 写失败会全部回滚。

重置 receipt 只保留受保护的操作哈希，十五分钟内支持相同请求重试；不会保存明文邮件令牌或密码等价凭据，也不保留旧 vault。相同请求只切换一次代际；修改新凭据或内容拒绝。

断网后先查询：

```text
POST /v1/accounts/{id}/account-reset/status
{accountGeneration,challengeId,token}
```

返回 `{state:"pending"|"complete",accountId,accountGeneration}`。查询需要同一邮件证明；不要凭未收到响应就重复新建账号或重新生成恢复根。完成后必须正常登录并走首台可信手机初始化流程，重置不直接发行可信设备。

## Docker / Node SMTP

生产配置采用部署 secrets，仓库不保存真实值：`HARMONIA_SMTP_HOST`、`HARMONIA_SMTP_PORT`、`HARMONIA_SMTP_USER`、`HARMONIA_SMTP_PASSWORD`、`HARMONIA_MAIL_FROM`。端口只接受 465 隐式 TLS 或 587 强制 STARTTLS；认证前必须验证 TLS，最低 TLS 1.2，拒绝不可信证书，禁用 logger/debug，不允许明文降级。设置部分字段而缺其他必需项会拒绝启动，不静默切换不安全模式。

Nodemailer 发送的是中文纯文本事务邮件，没有入站邮件依赖。隔离测试使用随机 loopback 端口、临时 CA、假凭据和 `.invalid` 收件人；不会连接真实 SMTP。

## Workers Email Service

使用新官方 `send_email` 绑定 `EMAIL` 和结构化 `SendEmail.send({from,to,subject,text})`，不使用 worker-mailer 的 opportunistic STARTTLS 或 AUTH debug 路径。[官方 Workers API](https://developers.cloudflare.com/email-service/api/send-emails/workers-api/) 定义 builder 与发送响应。

`EMAIL_FROM` 默认空，未配置发送地址/绑定时失败关闭。本轮没有启用发信域名、连接真实邮件凭据或发送真实邮件。未来发送地址必须来自已启用 Email Service 的域名；任意收件人需要 Workers Paid，免费发送限账号已验证目标，不承诺公开注册全部免费。[官方价格](https://developers.cloudflare.com/email-service/platform/pricing/)、[发送绑定约束](https://developers.cloudflare.com/email-service/configuration/send-bindings/) 给出当前规则。

D1 只保留 `email` 与 `account_id`，通过唯一约束原子预留路由身份。每账号 DO 保存唯一权威密码验证值、代际、验证状态、证明、重置 receipt 和全部安全状态。中断留下的无账号目录预留可由后续注册填充；已有账号绝不覆盖。账号重置不需要跨 D1/DO 同步安全代际，避免撤销竞态。

[官方本地模拟器](https://developers.cloudflare.com/email-service/local-development/sending/) 会记录并落盘邮件内容；只允许合成测试内容，不能拿真实证明进行 `wrangler dev` 日志测试，更不能设置 remote 绑定偷偷发送邮件。本仓库 workerd 测试使用只存在测试入口的捕获发送器，生产不包含它。

## 测试与剩余边界

Node 合成测试覆盖独立开关、验证后登录仍不可信、证明用途/代际/期限/回放、发送失败、哈希保存、明确破坏确认、旧权限失效、事务外 Argon2 后 CAS、SQL 写失败回滚、并发相同请求幂等与 SQLite 重开。实际本地 workerd 测试覆盖注册、D1 预留、DO 验证/登录/重置、旧代际拒绝、新凭据登录和已有账号不覆盖。

真正 SMTP 465/587 外部服务器互通、Email Service 真实发送权限/域名/投递、垃圾邮件风险和生产入口限流仍未验收。手机输入、强认证及完整用户流程还须单独集成测试。这些局部通过不代表生产可用。
