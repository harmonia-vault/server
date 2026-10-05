import test from "node:test";
import assert from "node:assert/strict";
import { codeEmail } from "../src/email-templates.js";

test("验证码以无内容横条分组，复制结果不含分隔字符", () => {
  const m = codeEmail({ purpose: "verification", email: "user@example.com", code: "K7QF9XMD", minutes: 15 });
  assert.equal(m.subject, "Harmonia 邮箱验证码");
  assert.match(m.text, /验证码：K7QF9XMD\n15 分钟内有效/);
  assert.match(m.html!, /K7QF<span[^>]*><\/span>9XMD/);
  assert.equal(m.html!.match(/K7QF/g)!.length, 1);
  assert.doesNotMatch(m.subject + m.html!.slice(0, m.html!.indexOf("<table")), /K7QF|9XMD/);
  assert.doesNotMatch(m.text + m.html!, /重置后数据无法找回/);
});

test("重置邮件带不可恢复警告并使用实际剩余分钟", () => {
  const m = codeEmail({ purpose: "reset", email: "user@example.com", code: "R4WN8TJE", minutes: 7 });
  assert.equal(m.subject, "Harmonia 账号重置验证码");
  assert.match(m.text, /重置后数据无法找回/);
  assert.match(m.html!, /重置后数据无法找回/);
  assert.match(m.html!, /7 分钟内有效/);
});

test("收件地址在 HTML 中转义", () => {
  const m = codeEmail({ purpose: "verification", email: "<b>\"x'&@example.com", code: "K7QF9XMD", minutes: 15 });
  assert.match(m.html!, /&lt;b&gt;&quot;x&#39;&amp;@example\.com/);
  assert.doesNotMatch(m.html!, /<b>/);
});

test("拒绝非规范验证码与有效期", () => {
  for (const input of [{ code: "k7qf9xmd", minutes: 15 }, { code: "K7QF-9XMD", minutes: 15 }, { code: "K7QF9XM", minutes: 15 }, { code: "K7QF9XMD", minutes: 0 }]) {
    assert.throws(() => codeEmail({ purpose: "verification", email: "user@example.com", ...input }), /email_template_input_invalid/);
  }
});
