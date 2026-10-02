import nodemailer, { type TransportOptions } from "nodemailer";
import { Fault } from "./model.js";
export interface SmtpConfig { host: string; port: 465 | 587; user: string; password: string }
export function smtpOptions(config: SmtpConfig): TransportOptions & Record<string, unknown> {
  if (!config.host || ![465, 587].includes(config.port)) throw new Fault(400, "smtp_tls_required");
  return { host: config.host, port: config.port, secure: config.port === 465, requireTLS: true,
    auth: { user: config.user, pass: config.password }, tls: { minVersion: "TLSv1.2", rejectUnauthorized: true },
    logger: false, debug: false, connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000 };
}
// Library adapter only. No public mail route or test sends real mail in M1.
export function smtpTransport(config: SmtpConfig): ReturnType<typeof nodemailer.createTransport> {
  return nodemailer.createTransport(smtpOptions(config));
}
