import { Fault } from "./model.js";
export interface Email { to: string; subject: string; text: string; html?: string }
export interface EmailTransport { send(message: Email): Promise<void> }
export function sender(value: string): string {
  if (typeof value !== "string" || value.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(value)) throw new Fault(400, "email_sender_invalid");
  return value.toLowerCase();
}
// 新官方绑定；结构化 builder 不使用 opportunistic SMTP，也不输出平台错误内容。
export function cloudflareEmail(binding: SendEmail | undefined, from: string | undefined): EmailTransport | undefined {
  if (!binding || !from) return undefined;
  const address = sender(from);
  return { async send(message) { await binding.send({ from: address, to: message.to, subject: message.subject, text: message.text, ...(message.html ? { html: message.html } : {}) }); } };
}
