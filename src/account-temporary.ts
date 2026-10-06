import type { Account } from './model.js';
import type { RecoveryDAGAccount } from './recovery-dag-account.js';
import type { TemporaryRecord } from './temporary-store.js';

const arrays = ['sessions', 'deviceChallenges', 'emailProofs', 'notificationTickets', 'bootChallenges', 'recoveryChallenges'] as const;

export function splitAccount(account: Account): { persistent: Account; temporary: TemporaryRecord[] } {
  const persistent = structuredClone(account) as RecoveryDAGAccount, temporary: TemporaryRecord[] = [];
  const add = (namespace: string, key: string, value: unknown, expiresAt: number): void => {
    temporary.push({ namespace, owner: account.id, key, value, expiresAt });
  };
  for (const field of arrays) {
    // 数组的顺序参与容量淘汰，使用序号作为 TTL 键并按写入顺序读取。
    for (const [index, value] of (persistent[field] ?? []).entries()) add(field, String(index), value, value.expiresAt);
    delete (persistent as unknown as Record<string, unknown>)[field];
  }
  if (persistent.resetReceipt) {
    add('resetReceipt', 'receipt', persistent.resetReceipt, persistent.resetReceipt.expiresAt);
    delete persistent.resetReceipt;
  }
  for (const [key, value] of Object.entries(persistent.vaultInitializations ?? {})) {
    if (!value.complete) { add('vaultInitializations', key, value, value.expiresAt); delete persistent.vaultInitializations![key]; }
  }
  for (const [key, value] of Object.entries(persistent.dagPairingSessions ?? {})) {
    if (value.sequence === undefined) { add('dagPairingSessions', key, value, Number(value.context.expiresAt)); delete persistent.dagPairingSessions![key]; }
  }
  // recoveryDAGChallenges / recoveredDAGChallenges 同时是恢复操作日志。
  // 关闭操作和已接受请求的幂等查询依赖原挑战证据；其截止时间只限制执行。
  return { persistent, temporary };
}

export function joinAccount(persistent: Account, temporary: TemporaryRecord[]): Account {
  const account = persistent as unknown as Record<string, unknown>;
  for (const field of arrays) account[field] = [];
  for (const record of temporary) {
    if (arrays.includes(record.namespace as typeof arrays[number])) (account[record.namespace] as unknown[]).push(record.value);
    else if (record.namespace === 'resetReceipt') account.resetReceipt = record.value;
    else if (record.namespace === 'vaultInitializations' || record.namespace === 'dagPairingSessions') {
      const map = (account[record.namespace] ??= {}) as Record<string, unknown>;
      Object.defineProperty(map, record.key, { value: record.value, enumerable: true, writable: true, configurable: true });
    }
  }
  return persistent;
}
