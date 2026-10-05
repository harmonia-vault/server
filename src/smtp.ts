import nodemailer, { type TransportOptions } from "nodemailer";
import { sender, type EmailTransport } from "./email-transport.js";
import { Fault } from "./model.js";
export interface SmtpConfig { host: string; port: 465 | 587; user: string; password: string }
export function smtpOptions(config: SmtpConfig): TransportOptions & Record<string, unknown> {
  if (!config.host || ![465, 587].includes(config.port)) throw new Fault(400, "smtp_tls_required");
  return { host: config.host, port: config.port, secure: config.port === 465, requireTLS: true,
    auth: { user: config.user, pass: config.password }, tls: { minVersion: "TLSv1.2", rejectUnauthorized: true },
    logger: false, debug: false, connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000 };
}
// 严格 TLS 发送适配；测试只连接隔离回环 SMTP，不使用真实邮箱凭据。
export function smtpTransport(config: SmtpConfig): ReturnType<typeof nodemailer.createTransport> {
  return nodemailer.createTransport(smtpOptions(config));
}

export function smtpEmail(config: SmtpConfig, from: string): EmailTransport {
  const transport = smtpTransport(config), address = sender(from);
  return { async send(message) { await transport.sendMail({ from: address, to: message.to, subject: message.subject, text: message.text, ...(message.html ? { html: message.html } : {}) }); } };
}
