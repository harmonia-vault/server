import { Fault } from "./model.js";
/** 标准 JSON 语法仍交给 JSON.parse；此前扫描拒绝重复成员和深层结构。 */
export function strictRecoveryJson(raw: Uint8Array): Record<string, unknown> {
    if (raw.length > 2 * 1024 * 1024)
        throw new Fault(413, "body_too_large");
    let text: string;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    }
    catch {
        throw new Fault(400, "json_invalid");
    }
    let cursor = 0;
    const ws = () => { while (/\s/.test(text[cursor] ?? "") && cursor < text.length)
        cursor++; };
    function string(): string { const start = cursor++; while (cursor < text.length) {
        const c = text[cursor++];
        if (c === '"') {
            try {
                return JSON.parse(text.slice(start, cursor)) as string;
            }
            catch {
                throw new Fault(400, "json_invalid");
            }
        }
        if (c === '\\')
            cursor++;
    } throw new Fault(400, "json_invalid"); }
    function value(depth: number): void {
        if (depth > 64)
            throw new Fault(400, "json_invalid");
        ws();
        const c = text[cursor];
        if (c === '"') {
            string();
            return;
        }
        if (c === '{' || c === '[') {
            cursor++;
            ws();
            const end = c === '{' ? '}' : ']';
            if (text[cursor] === end) {
                cursor++;
                return;
            }
            const members = new Set<string>();
            while (cursor < text.length) {
                if (c === '{') {
                    if (text[cursor] !== '"')
                        throw new Fault(400, "json_invalid");
                    const key = string();
                    if (members.has(key))
                        throw new Fault(400, "json_invalid");
                    members.add(key);
                    ws();
                    if (text[cursor++] !== ':')
                        throw new Fault(400, "json_invalid");
                }
                value(depth + 1);
                ws();
                const delimiter = text[cursor++];
                if (delimiter === end)
                    return;
                if (delimiter !== ',')
                    throw new Fault(400, "json_invalid");
                ws();
            }
            throw new Fault(400, "json_invalid");
        }
        const start = cursor;
        while (cursor < text.length && !/[\s,}\]]/.test(text[cursor]!))
            cursor++;
        if (start === cursor)
            throw new Fault(400, "json_invalid");
    }
    try {
        value(0);
        ws();
        if (cursor !== text.length)
            throw new Error();
        const result: unknown = JSON.parse(text);
        if (!result || typeof result !== "object" || Array.isArray(result))
            throw new Error();
        return result as Record<string, unknown>;
    }
    catch {
        throw new Fault(400, "json_invalid");
    }
}
export async function strictRecoveryBody(request: Request): Promise<Record<string, unknown>> {
    if (!request.headers.get("content-type")?.startsWith("application/json"))
        throw new Fault(415, "json_required");
    const reader = request.body?.getReader();
    if (!reader)
        throw new Fault(400, "body_required");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        while (true) {
            const part = await reader.read();
            if (part.done)
                break;
            size += part.value.length;
            if (size > 2 * 1024 * 1024) {
                await reader.cancel();
                throw new Fault(413, "body_too_large");
            }
            chunks.push(part.value);
        }
    }
    finally {
        reader.releaseLock();
    }
    return strictRecoveryJson(Buffer.concat(chunks));
}
