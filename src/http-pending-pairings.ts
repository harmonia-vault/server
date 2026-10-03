import { Fault } from "./model.js";
import type { Store } from "./store.js";
import { requestAuth } from "./http.js";
import { PendingPairingService } from "./pending-pairings.js";
export async function pendingPairingsRoute(request: Request, store: Store): Promise<{ handled: boolean; result?: unknown }> {
  const url = new URL(request.url), match = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/pairing-requests-v([34])$/);
  if (!match) return { handled: false };
  if (request.method !== "GET") throw new Fault(405, "method_not_allowed");
  if (url.search) throw new Fault(400, "query_forbidden");
  return { handled: true, result: await new PendingPairingService(store).list(match[1]!, requestAuth(request), match[2] as "3" | "4") };
}
