import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer as tcpServer, type Socket, type Server } from "node:net";
import { createServer as tlsServer, createSecureContext, TLSSocket } from "node:tls";
import nodemailer from "nodemailer";
import type SMTPTransport from "nodemailer/lib/smtp-transport/index.js";
import { smtpOptions } from "../src/smtp.js";
// 仅隔离回环 SMTP；随机临时证书不进入仓库，消息不交给任何真实邮件服务器。
async function fixture(mode: "tls" | "starttls" | "downgrade", run: (port: number, ca: Buffer, counts: { auth: number; clearAuth: number; delivered: number }) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-smtp-tls-")), keyFile = join(dir, "key.pem"), certFile = join(dir, "ca.pem"), config = join(dir, "openssl.cnf");
  writeFileSync(config, "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\n");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile, "-out", certFile, "-days", "1", "-config", config], { stdio: "ignore" });
  const key = readFileSync(keyFile), ca = readFileSync(certFile), secureContext = createSecureContext({ key, cert: ca, minVersion: "TLSv1.2" });
  const sockets = new Set<Socket>(), counts = { auth: 0, clearAuth: 0, delivered: 0 };
  function attach(socket: Socket, encrypted: boolean, greeting = true): void {
    sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => sockets.delete(socket));
    if (greeting) socket.write("220 synthetic.local ESMTP\r\n");
    let buffered = "", dataMode = false;
    const onData = (chunk: Uint8Array): void => {
      buffered += new TextDecoder().decode(chunk);
      while (buffered.includes("\r\n")) {
        const i = buffered.indexOf("\r\n"), line = buffered.slice(0, i); buffered = buffered.slice(i + 2);
        if (dataMode) { if (line === ".") { counts.delivered++; dataMode = false; socket.write("250 synthetic queued\r\n"); } continue; }
        if (/^EHLO|^HELO/.test(line)) socket.write(mode === "starttls" && !encrypted ? "250-synthetic.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n" : "250-synthetic.local\r\n250 AUTH PLAIN\r\n");
        else if (line === "STARTTLS") {
          if (mode === "downgrade") { socket.write("454 TLS unavailable\r\n"); continue; }
          socket.removeListener("data", onData);
          socket.write("220 start TLS\r\n", () => {
            const secured = new TLSSocket(socket, { isServer: true, secureContext }); secured.on("error", () => {}); attach(secured, true, false);
          }); return;
        } else if (line.startsWith("AUTH ")) { counts.auth++; if (!encrypted) counts.clearAuth++; socket.write("235 synthetic authenticated\r\n"); }
        else if (line.startsWith("MAIL FROM:") || line.startsWith("RCPT TO:")) socket.write("250 OK\r\n");
        else if (line === "DATA") { dataMode = true; socket.write("354 send data\r\n"); }
        else if (line === "QUIT") { socket.end("221 Bye\r\n"); }
        else socket.write("250 OK\r\n");
      }
    };
    socket.on("data", onData);
  }
  const server: Server = mode === "tls" ? tlsServer({ key, cert: ca, minVersion: "TLSv1.2" }, socket => attach(socket, true)) : tcpServer(socket => attach(socket, false));
  server.on("error", () => {});
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); if (!address || typeof address === "string") throw new Error("synthetic SMTP bind failed");
  try { await run(address.port, ca, counts); }
  finally { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true }); }
}
function options(port: number, mode: "tls" | "starttls", ca?: Buffer): SMTPTransport.Options {
  const value = smtpOptions({ host: "127.0.0.1", port: mode === "tls" ? 465 : 587, user: "synthetic-user", password: "synthetic-not-a-real-secret" }) as SMTPTransport.Options;
  // 仅测试将严格生产端口改为随机回环端口，并信任本次测试临时 CA。
  value.port = port; if (ca) value.tls = { ...value.tls, ca };
  value.connectionTimeout = 3000; value.greetingTimeout = 3000; value.socketTimeout = 3000;
  return value;
}
async function send(value: SMTPTransport.Options): Promise<void> {
  const transport = nodemailer.createTransport(value);
  try { await transport.sendMail({ from: "noreply@example.invalid", to: "synthetic@example.invalid", subject: "隔离 TLS 合成测试", text: "没有真实账号或凭据" }); }
  finally { transport.close(); }
}
test("SMTP implicit TLS and required STARTTLS authenticate only after verified TLS with ephemeral test CA", async () => {
  for (const mode of ["tls", "starttls"] as const) await fixture(mode, async (port, ca, counts) => {
    await send(options(port, mode, ca)); assert.equal(counts.auth, 1); assert.equal(counts.clearAuth, 0); assert.equal(counts.delivered, 1);
  });
});
test("SMTP refuses plaintext downgrade and untrusted certificates before sending AUTH or message", async () => {
  await fixture("downgrade", async (port, ca, counts) => { await assert.rejects(send(options(port, "starttls", ca))); assert.equal(counts.auth, 0); assert.equal(counts.delivered, 0); });
  await fixture("tls", async (port, _, counts) => { await assert.rejects(send(options(port, "tls"))); assert.equal(counts.auth, 0); assert.equal(counts.delivered, 0); });
});
