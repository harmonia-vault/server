# Harmonia Server

Harmonia（和弦）的自托管服务端，让手机与电脑之间的环境变量保持同步。你可以在手机上管理变量，为不同设备分配所需的环境和权限，并将数据保存在自己的服务中。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harmonia-vault/server)

## 项目用途

- **集中管理环境变量**：按项目或用途组织环境，在已授权设备间同步更新。
- **按设备分配权限**：为设备选择可访问的环境，设置只读、读写或管理权限，以及有效期；需要时可撤销授权。
- **加密存储**：变量在客户端加密，服务端存储和同步密文，不解密变量内容。
- **自主托管**：使用自己的服务地址，配合 [Harmonia 手机端](https://github.com/harmonia-vault/mobile)和[命令行客户端](https://github.com/harmonia-vault/core-go)使用。

## 一键部署到 Workers

准备好 Cloudflare 和 GitHub 账号，然后点击上方 **Deploy to Cloudflare** 按钮。

1. **准备邮件服务**：在 [Cloudflare Email Service](https://developers.cloudflare.com/email-service/) 中启用并验证发信域名，用于发送邮箱验证和账号重置邮件。
2. **创建服务**：在部署向导中连接 GitHub，选择 Cloudflare 账号，确认新仓库和 Worker 的名称。向导会复制本仓库并创建所需资源。
3. **填写配置**：保留 `EMAIL` 邮件发送绑定，将 `EMAIL_FROM` 填为已验证域名下的发件地址；其余选项见下表。
4. **获取地址**：部署完成后，复制 Worker 的 HTTPS 地址，例如 `https://harmonia-server.<你的子域名>.workers.dev`，供客户端连接。

部署流程详见 [Cloudflare 官方说明](https://developers.cloudflare.com/workers/platform/deploy-buttons/)。新仓库会连接 Workers Builds，后续推送到生产分支会自动更新服务。

## 配置

在部署向导或 Worker 设置中配置以下变量：

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `EMAIL_FROM` | 未设置 | 邮件发件地址，例如 `noreply@example.com`。只填邮箱地址，须使用已启用 Email Service 的域名。 |
| `ALLOW_REGISTRATION` | `false` | 是否允许新用户注册。设为 `true` 后开放注册；关闭时，空实例仍允许注册首个账号。 |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | 新注册账号是否必须验证邮箱。保持开启时，须先配置好邮件服务。 |

首次部署后，请先完成自己的账号注册，再分享服务地址。邮箱验证要求在账号注册时确定，之后修改配置不会取消已有待验证账号的验证要求。

## 开始使用

1. 在 Harmonia 手机端填写你的 **HTTPS 服务地址**，注册账号并按提示完成邮箱验证。
2. 按提示初始化账号，妥善保存恢复码，并完成确认。
3. 创建环境并添加变量。在电脑的命令行客户端连接同一服务地址，发起设备配对。
4. 在手机上核对配对请求，选择允许访问的环境、权限和有效期。批准后，在电脑上选择要启用的环境，即可同步使用。

服务地址填写基础地址即可，无需添加 `/v1` 等接口路径。日常管理通过手机端和命令行客户端完成。

当前为实验性软件，暂不建议用于生产环境中的真实秘密。

## 许可证

[MIT](LICENSE)
