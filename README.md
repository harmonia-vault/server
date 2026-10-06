> [!WARNING]
> 项目正处于开发阶段，仅供测试使用。

# Harmonia Server

Harmonia（和弦）是一个自托管的环境变量同步工具：在手机上集中管理环境变量，按设备授权，同步到电脑和运行环境中使用。

本仓库是 Harmonia 的服务端，负责账号与数据同步，部署在 Cloudflare Workers 上。需配合 [手机端](https://github.com/harmonia-vault/mobile)与[命令行客户端](https://github.com/harmonia-vault/core-go)使用。

## 部署

需要 Cloudflare 与 GitHub 账号，以及一个用于发信的域名。

### Fork 部署（推荐）

1. 在 Cloudflare 中启用 [Email Service](https://developers.cloudflare.com/email-service/) 并验证发信域名，用于发送注册和账号重置验证码。
2. [Fork 本仓库](https://github.com/harmonia-vault/server/fork)，按[配置](#配置)填写发件地址。
3. 在 Cloudflare 的 **My Profile → API Tokens** 中，使用 **Edit Cloudflare Workers** 模板创建令牌，并添加 **Account → D1 → Edit** 权限。
4. 在 **Workers & Pages → Create application** 中连接自己的 Fork，选择 `main` 分支和刚创建的令牌，Worker 名称填 `harmonia-server`。
5. 完成部署，记录 Worker 的 HTTPS 地址。

### 一键部署

完成上述发信域名设置后，也可使用一键部署，在配置页面填写[配置项](#配置)。后续通过 [Actions 更新](#actions-更新)。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harmonia-vault/server)

## 配置

配置项位于仓库的 `wrangler.jsonc` 文件中的 `vars`，修改后提交即可部署：

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

### Fork 更新

在自己的仓库点击 **Sync fork → Update branch**，Cloudflare 会自动部署更新。

### Actions 更新

一键部署创建的仓库使用此方式，无需创建 GitHub 个人令牌。

1. 首次使用：将[更新入口](https://github.com/harmonia-vault/server/blob/main/.github/workflows/sync-upstream.yml)复制到自己仓库的 `.github/workflows/sync-upstream.yml`；在 **Settings → Actions → General → Workflow permissions** 中勾选 **Allow GitHub Actions to create and approve pull requests**。
2. 在 **Actions → 更新服务 → Run workflow** 中选择 Cloudflare 绑定的分支并运行。
3. 合并生成的 Pull Request，Cloudflare 会自动部署更新。

相比 Fork，此方式首次需要手动设置，每次更新需要运行 Actions 并合并 PR；仓库中的工作流文件不会自动更新，入口或权限要求变化时仍需手动调整。

## 注意事项

- 部署后请先注册自己的账号，再分享服务地址。

## 许可证

[MIT](LICENSE)
