import { createServer, type IncomingMessage, type Server } from "node:http";
import { WebSocketServer, type WebSocket } from "ws";
import { bodyLimit, requestAuth, route } from "./http.js";
import { Fault } from "./model.js";
import { protocolMajorHeader, requestProtocolMajor } from "./protocol-info.js";
import { NotificationAuthority, notificationPath, type NotificationState } from "./notifications.js";
import type { VaultService } from "./service.js";
import { canonicalClientIP } from "./email-rate-limit.js";
export function incomingClientIP(incoming: IncomingMessage, trustedProxyIPs: readonly string[] = []): string {
  const peer = canonicalClientIP(incoming.socket.remoteAddress);
  if (peer !== "unknown" && trustedProxyIPs.some(ip => canonicalClientIP(ip) === peer)) {
    const forwarded = incoming.headers["x-real-ip"];
    return canonicalClientIP(typeof forwarded === "string" ? forwarded : undefined);
  }
  return peer;
}
export function incomingRequest(incoming: IncomingMessage, data?: Uint8Array): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  if (!incoming.url?.startsWith("/")) throw new Fault(400, "target_invalid");
  return new Request(`http://127.0.0.1${incoming.url}`, { method: incoming.method ?? "GET", headers, ...(data === undefined ? {} : { body: data as BodyInit }) });
}
export function nodeServer(service: VaultService, extra?: (request: Request) => Promise<Response | undefined>, authority = new NotificationAuthority(service.store), trustedProxyIPs: readonly string[] = []): { server: Server; closeNotifications(): void } {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024, perMessageDeflate: false });
  wss.on("headers", headers => { headers.push(`${protocolMajorHeader}: 2`); });
  const peers = new Map<WebSocket, NotificationState>(); let timer: ReturnType<typeof setTimeout> | undefined;
  function refresh(): void {
    if (timer) clearTimeout(timer); timer = undefined;
    let deadline = Infinity;
    for (const [socket, state] of peers) {
      if (socket.readyState !== 1 || socket.bufferedAmount > 65536) { peers.delete(socket); socket.close(1013, "reconnect_required"); continue; }
      const next = authority.deliver(state, socket);
      if (!next) peers.delete(socket); else { peers.set(socket, next.state); deadline = Math.min(deadline, next.expiresAt); }
    }
    if (Number.isFinite(deadline)) { timer = setTimeout(refresh, Math.max(1, Math.min(2147483647, deadline * 1000 - Date.now()))); timer.unref(); }
  }
  const unobserve = service.store.onCommit?.(accountId => { if (Array.from(peers.values()).some(s => s.accountId === accountId)) refresh(); });
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Uint8Array[] = []; let size = 0;
      const pathname = new URL(incoming.url ?? "/", "http://127.0.0.1").pathname, limit = bodyLimit(incoming.method ?? "GET", pathname);
      for await (const chunk of incoming.iterator({ destroyOnReturn: false })) { size += Buffer.byteLength(chunk); if (size > limit) { incoming.resume(); throw new Fault(413, "body_too_large"); } chunks.push(Buffer.from(chunk)); }
      const request = incomingRequest(incoming, ["GET", "HEAD"].includes(incoming.method ?? "GET") ? undefined : Buffer.concat(chunks));
      const response = await extra?.(request) ?? await route(request, service, incomingClientIP(incoming, trustedProxyIPs));
      outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) { const fault = e instanceof Fault ? e : new Fault(400, "request_invalid"); if (!outgoing.headersSent) outgoing.writeHead(fault.status, { "content-type": "application/json", "cache-control": "no-store", [protocolMajorHeader]: "2" }); outgoing.end(JSON.stringify({ error: fault.code })); }
  });
  server.on("upgrade", (incoming, socket, head) => {
    socket.on("error", () => {});
    void (async () => {
      const request = incomingRequest(incoming); requestProtocolMajor(request); const accountId = notificationPath(request);
      if (peers.size >= 256) throw new Fault(429, "notification_capacity_reached");
      const credentials = requestAuth(request);
      if (Array.from(peers.values()).filter(p => p.accountId === accountId && p.deviceId === credentials.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      const state = await authority.consume(accountId, credentials);
      if (socket.destroyed) return;
      if (peers.size >= 256 || Array.from(peers.values()).filter(p => p.accountId === accountId && p.deviceId === credentials.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      wss.handleUpgrade(incoming, socket, head, ws => {
        ws.on("error", () => {}); ws.on("close", () => { peers.delete(ws); refresh(); });
        ws.on("message", () => { authority.deliver(peers.get(ws) ?? state, ws); ws.close(1008, "notifications_only"); });
        peers.set(ws, state); refresh();
      });
    })().catch(e => { const fault = e instanceof Fault ? e : new Fault(400, "request_invalid"); if (!socket.destroyed) socket.end(`HTTP/1.1 ${fault.status} Rejected\r\nContent-Type: application/json\r\n${protocolMajorHeader}: 2\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n${JSON.stringify({ error: fault.code })}`); });
  });
  return { server, closeNotifications: () => { unobserve?.(); if (timer) clearTimeout(timer); for (const peer of peers.keys()) peer.close(1001, "server_stopping"); peers.clear(); wss.close(); } };
}
