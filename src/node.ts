import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { nodeStore } from "./node-store.js";
import { VaultService } from "./service.js";
import { smtpEmail } from "./smtp.js";
import { Fault } from "./model.js";
import type { EmailTransport } from "./email-transport.js";
import { nodeServer } from "./node-runtime.js";
const path = process.env.HARMONIA_DATABASE ?? "/data/harmonia.sqlite";
mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
const { store, sql } = nodeStore(path);
let mail: EmailTransport | undefined;
if (process.env.HARMONIA_SMTP_HOST || process.env.HARMONIA_SMTP_USER || process.env.HARMONIA_SMTP_PASSWORD || process.env.HARMONIA_MAIL_FROM) {
  const port = Number(process.env.HARMONIA_SMTP_PORT ?? "465");
  if (![465, 587].includes(port) || !process.env.HARMONIA_SMTP_HOST || !process.env.HARMONIA_SMTP_USER || !process.env.HARMONIA_SMTP_PASSWORD || !process.env.HARMONIA_MAIL_FROM) throw new Fault(503, "email_configuration_invalid");
  mail = smtpEmail({ host: process.env.HARMONIA_SMTP_HOST, port: port as 465 | 587, user: process.env.HARMONIA_SMTP_USER, password: process.env.HARMONIA_SMTP_PASSWORD }, process.env.HARMONIA_MAIL_FROM);
}
const service = new VaultService(store, {
  allowRegistration: process.env.HARMONIA_ALLOW_REGISTRATION === "true",
  requireEmailVerification: process.env.HARMONIA_REQUIRE_EMAIL_VERIFICATION !== "false",
}, undefined, undefined, mail);
// 只监听 loopback；远程设备访问须通过明确的 TLS 代理边界。
const { server, closeNotifications } = nodeServer(service);
if (process.env.HARMONIA_BIND && process.env.HARMONIA_BIND !== "127.0.0.1") throw new Error("remote_plain_http_binding_disabled");
server.listen(Number(process.env.HARMONIA_PORT ?? "8787"), "127.0.0.1");
function stop(): void { closeNotifications(); server.close(() => { sql.close(); process.exit(0); }); }
process.on("SIGTERM", stop); process.on("SIGINT", stop);
