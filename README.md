# Harmonia Server

Harmonia（和弦）是一个自托管的环境变量同步工具：在手机上集中管理环境变量，按设备授权，同步到电脑和运行环境中使用。

本仓库是 Harmonia 的服务端，负责账号与数据同步，可一键部署到 Cloudflare Workers。变量在客户端加密后上传，服务端仅保存密文。需配合 [手机端](https://github.com/harmonia-vault/mobile)与[命令行客户端](https://github.com/harmonia-vault/core-go)使用。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harmonia-vault/server)

## 部署

需要 Cloudflare 与 GitHub 账号，以及一个用于发信的域名。

1. 在 Cloudflare 中启用 [Email Service](https://developers.cloudflare.com/email-service/) 并验证发信域名，用于发送注册和账号重置验证码。
2. 点击上方 **Deploy to Cloudflare**，连接 GitHub，确认仓库与 Worker 名称。
3. 在配置页面将 `EMAIL_FROM` 设为该域名下的发件地址，其余配置见下文。
4. 部署完成后，记录 Worker 的 HTTPS 地址，例如 `https://harmonia-server.<子域名>.workers.dev`。

## 配置

可在部署页面或 Worker 的 **Settings → Variables and Secrets** 中修改：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `EMAIL_FROM` | 无（必填） | 发件地址，例如 `noreply@example.com` |
| `ALLOW_REGISTRATION` | `false` | 是否开放注册；关闭时仅允许注册首个账号 |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | 注册时是否验证邮箱 |

## 使用

1. 在手机端填写服务地址，注册账号、保存恢复码，并创建环境和变量。
2. 在电脑上使用命令行客户端连接同一地址并发起配对，在手机上批准后即可同步。

详细步骤见 [手机端](https://github.com/harmonia-vault/mobile)与[命令行客户端](https://github.com/harmonia-vault/core-go)。

## 更新

一键部署会在你的 GitHub 账号下创建独立仓库，不会自动同步本仓库的更新，需手动更新：

1. 确认自己的仓库包含 [`.github/workflows/sync-upstream.yml`](https://github.com/harmonia-vault/server/blob/main/.github/workflows/sync-upstream.yml)；如缺失，在相同路径新建该文件并复制内容。
2. 在 **Actions → 更新服务** 中运行工作流。首次运行会提示完成授权，按提示设置后重新运行。
3. 按生成的 Pull Request 中的说明合并，Cloudflare 将自动部署新版本。

通过 Fork 部署的仓库，可直接使用 GitHub 的 **Sync fork → Update branch** 更新。

## 注意事项

- 部署后请先注册自己的账号，再分享服务地址。
- 项目处于实验阶段，请勿用于生产环境的凭据。

## 许可证

[MIT](LICENSE)
