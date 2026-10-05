import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";

const syncScript = fileURLToPath(new URL("../scripts/sync-upstream.sh", import.meta.url));
const baseScript = fileURLToPath(new URL("../scripts/upstream-base.mjs", import.meta.url));

function fixture(t: TestContext, standalone = false) {
  const root = mkdtempSync(join(tmpdir(), "harmonia-sync-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const upstream = join(root, "upstream");
  const origin = join(root, "origin.git");
  const deployed = join(root, "deployed");
  const bin = join(root, "bin");
  const summary = join(root, "summary.md");
  const apiRecord = join(root, "pr.json");
  mkdirSync(upstream);
  mkdirSync(bin);
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "Synthetic Tester",
    GIT_AUTHOR_EMAIL: "synthetic@example.invalid",
    GIT_COMMITTER_NAME: "Synthetic Tester",
    GIT_COMMITTER_EMAIL: "synthetic@example.invalid",
    GIT_TERMINAL_PROMPT: "0",
    GH_TOKEN: "synthetic-test-token",
    PATH: `${bin}:${process.env.PATH}`,
    GITHUB_REPOSITORY: "synthetic/deployment",
    GITHUB_REF_NAME: "production",
    GITHUB_RUN_ID: "42",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_STEP_SUMMARY: summary,
    RUNNER_TEMP: root,
    TEST_PR_RECORD: apiRecord,
  };
  function git(cwd: string, ...args: string[]): string {
    return execFileSync("git", args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  }
  function commit(cwd: string, message: string): string {
    git(cwd, "add", ".");
    git(cwd, "commit", "-m", message);
    return git(cwd, "rev-parse", "HEAD");
  }
  git(upstream, "init", "-b", "main");
  const template = {
    name: "harmonia-server",
    main: "src/worker.ts",
    compatibility_date: "2026-10-02",
    durable_objects: { bindings: [{ name: "ACCOUNTS", class_name: "AccountVault" }] },
    migrations: [{ tag: "v1", new_sqlite_classes: ["AccountVault"] }],
    d1_databases: [{ binding: "DIRECTORY", database_name: "harmonia-directory", database_id: "00000000-0000-0000-0000-000000000000" }],
    vars: { EMAIL_FROM: "", ALLOW_REGISTRATION: "false" },
  };
  function writeConfig(cwd: string, config: object): void {
    writeFileSync(join(cwd, "wrangler.jsonc"), `${JSON.stringify(config, null, 2)}\n`);
  }
  writeConfig(upstream, template);
  writeFileSync(join(upstream, "package.json"), '{"name":"harmonia-server","private":true}\n');
  mkdirSync(join(upstream, ".github/workflows"), { recursive: true });
  writeFileSync(join(upstream, ".github/workflows/check.yml"), "name: initial upstream workflow\n");
  writeFileSync(join(upstream, "version.txt"), "version one\n");
  commit(upstream, "initial upstream");
  git(root, "init", "--bare", origin);
  git(root, "clone", "--no-hardlinks", upstream, deployed);
  git(deployed, "remote", "set-url", "origin", origin);
  git(deployed, "remote", "add", "upstream", upstream);
  git(deployed, "switch", "-c", "production");
  const deploymentConfig = structuredClone(template);
  deploymentConfig.name = "my-deployed-harmonia";
  deploymentConfig.d1_databases[0]!.database_name = "my-directory";
  deploymentConfig.d1_databases[0]!.database_id = "11111111-2222-4333-8444-555555555555";
  deploymentConfig.vars.EMAIL_FROM = "hello@example.invalid";
  writeConfig(deployed, deploymentConfig);
  commit(deployed, "configure deployment");
  if (standalone) {
    git(deployed, "checkout", "--orphan", "imported");
    rmSync(join(deployed, ".github/workflows/check.yml"));
    writeFileSync(join(deployed, "package.json"), '{"name":"my-deployment","private":true}\n');
    writeFileSync(join(deployed, "wrangler.jsonc"), `// Deployment settings\n${JSON.stringify(deploymentConfig, null, 2)}\n`);
    commit(deployed, "source repo import");
    git(deployed, "branch", "-M", "production");
  }
  git(deployed, "push", "origin", "production");
  // Only the GitHub API boundary is simulated; merge, push and remote refs use real Git.
  writeFileSync(join(bin, "gh"), `#!${process.execPath}
const { readFileSync, writeFileSync } = require("node:fs");
const args = process.argv.slice(2);
if (args[0] === "pr" && args[1] === "list") {
  process.stdout.write(process.env.TEST_EXISTING_PR || "");
} else if (args[0] === "pr" && args[1] === "create") {
  if (process.env.TEST_CREATE_FAILURE) process.exit(1);
  const value = flag => args[args.indexOf(flag) + 1];
  writeFileSync(process.env.TEST_PR_RECORD, JSON.stringify({
    base: value("--base"), head: value("--head"),
    body: readFileSync(value("--body-file"), "utf8")
  }));
  console.log("https://github.com/synthetic/deployment/pull/1");
} else {
  process.exit(2);
}
`, { mode: 0o755 });
  function run(extraEnv: Record<string, string> = {}) {
    git(deployed, "fetch", "--no-tags", "upstream", "refs/heads/main:refs/remotes/upstream/main");
    writeFileSync(summary, "");
    return spawnSync("bash", [syncScript, baseScript], { cwd: deployed, env: { ...env, ...extraEnv }, encoding: "utf8" });
  }
  function advance(): string {
    writeFileSync(join(upstream, "version.txt"), "version two\n");
    return commit(upstream, "upstream update");
  }
  function refs(): string {
    return git(origin, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads");
  }
  return { root, upstream, origin, deployed, summary, apiRecord, template, deploymentConfig, git, commit, writeConfig, run, advance, refs };
}

test("同步代码、工作流和新增迁移，保留个人配置，生产分支等待 PR 合并", t => {
  const f = fixture(t);
  const before = f.git(f.origin, "rev-parse", "production");
  f.template.migrations.push({ tag: "v2", new_sqlite_classes: ["NewVault"] });
  f.writeConfig(f.upstream, f.template);
  mkdirSync(join(f.upstream, ".github/workflows"), { recursive: true });
  writeFileSync(join(f.upstream, ".github/workflows/check.yml"), "name: new upstream workflow\n");
  const upstreamCommit = f.advance();
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.git(f.origin, "rev-parse", "production"), before);
  const head = "sync-upstream/42-1";
  assert.equal(f.git(f.origin, "show", `${head}:version.txt`), "version two");
  const config = JSON.parse(f.git(f.origin, "show", `${head}:wrangler.jsonc`));
  assert.equal(config.name, "my-deployed-harmonia");
  assert.equal(config.d1_databases[0].database_id, "11111111-2222-4333-8444-555555555555");
  assert.equal(config.vars.EMAIL_FROM, "hello@example.invalid");
  assert.equal(config.migrations[1].tag, "v2");
  assert.match(f.git(f.origin, "show", `${head}:.github/workflows/check.yml`), /new upstream workflow/);
  assert.equal(f.git(f.origin, "rev-parse", `${head}^2`), upstreamCommit);
  const pr = JSON.parse(readFileSync(f.apiRecord, "utf8"));
  assert.equal(pr.base, "production");
  assert.equal(pr.head, head);
  assert.match(pr.body, /Create a merge commit/);
  assert.match(readFileSync(f.summary, "utf8"), /pull\/1/);

  // Simulate the user merging the PR. A repeat must be a no-op, and the next update must retain history.
  f.git(f.deployed, "switch", "production");
  f.git(f.deployed, "merge", "--no-ff", "--no-edit", head);
  f.git(f.deployed, "push", "origin", "production");
  const mergedRefs = f.refs();
  assert.equal(f.run({ GITHUB_RUN_ID: "43" }).status, 0);
  assert.equal(f.refs(), mergedRefs);
  writeFileSync(join(f.upstream, "version.txt"), "version three\n");
  f.commit(f.upstream, "next upstream update");
  const next = f.run({ GITHUB_RUN_ID: "44" });
  assert.equal(next.status, 0, next.stderr);
  assert.equal(f.git(f.origin, "show", "sync-upstream/44-1:version.txt"), "version three");
  assert.match(f.git(f.origin, "show", "sync-upstream/44-1:wrangler.jsonc"), /11111111-2222-4333-8444-555555555555/);
});

test("没有上游更新时不创建远端分支", t => {
  const f = fixture(t);
  const before = f.refs();
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.refs(), before);
  assert.match(readFileSync(f.summary, "utf8"), /已是最新版本/);
});

test("配置冲突时不推送任何分支，也不丢弃个人配置", t => {
  const f = fixture(t);
  f.template.name = "new-upstream-name";
  f.writeConfig(f.upstream, f.template);
  f.advance();
  const before = f.refs();
  const result = f.run();
  assert.equal(result.status, 1);
  assert.equal(f.refs(), before);
  assert.equal(f.git(f.deployed, "status", "--porcelain"), "");
  assert.deepEqual(JSON.parse(readFileSync(join(f.deployed, "wrangler.jsonc"), "utf8")), f.deploymentConfig);
  assert.match(readFileSync(f.summary, "utf8"), /wrangler\.jsonc/);
});

test("有待处理 PR 时保留待审内容，不重复创建分支", t => {
  const f = fixture(t);
  f.advance();
  const before = f.refs();
  const result = f.run({ TEST_EXISTING_PR: "https://github.com/synthetic/deployment/pull/8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.refs(), before);
  assert.match(readFileSync(f.summary, "utf8"), /pull\/8/);
  assert.equal(f.git(f.deployed, "branch", "--show-current"), "production");
});

test("来源快照不匹配时停止，不强行关联独立仓库", t => {
  const f = fixture(t);
  f.git(f.upstream, "checkout", "--orphan", "replacement");
  writeFileSync(join(f.upstream, "version.txt"), "unrelated project\n");
  f.commit(f.upstream, "unrelated root");
  f.git(f.upstream, "branch", "-f", "main", "HEAD");
  const before = f.refs();
  const result = f.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /找不到对应的部署版本/);
  assert.equal(f.refs(), before);
});

test("独立导入仓库核对来源后初始化，恢复被移除的工作流并保留实例修改", t => {
  const f = fixture(t, true);
  const source = f.git(f.upstream, "rev-parse", "HEAD");
  writeFileSync(join(f.deployed, "local-only.txt"), "user customization\n");
  f.commit(f.deployed, "local customization after import");
  f.git(f.deployed, "push", "origin", "production");
  const before = f.git(f.origin, "rev-parse", "production");
  f.advance();
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.git(f.origin, "rev-parse", "production"), before);
  const head = "sync-upstream/42-1";
  assert.equal(f.git(f.origin, "show", `${head}:.github/upstream-base`), source);
  assert.equal(f.git(f.origin, "show", `${head}:version.txt`), "version two");
  assert.equal(f.git(f.origin, "show", `${head}:local-only.txt`), "user customization");
  assert.match(f.git(f.origin, "show", `${head}:.github/workflows/check.yml`), /initial upstream workflow/);
  assert.match(f.git(f.origin, "show", `${head}:package.json`), /my-deployment/);
  assert.match(f.git(f.origin, "show", `${head}:wrangler.jsonc`), /11111111-2222-4333-8444-555555555555/);
});

test("源代码已是最新的独立导入仍生成初始化 PR，合并后再次运行无需同步", t => {
  const f = fixture(t, true);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(f.git(f.origin, "show", "sync-upstream/42-1:.github/upstream-base"), /^[a-f0-9]{40}$/);
  f.git(f.deployed, "switch", "production");
  f.git(f.deployed, "merge", "--no-ff", "--no-edit", "sync-upstream/42-1");
  f.git(f.deployed, "push", "origin", "production");
  const before = f.refs();
  const repeated = f.run({ GITHUB_RUN_ID: "43" });
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.equal(f.refs(), before);
  assert.match(readFileSync(f.summary, "utf8"), /已是最新版本/);
});

test("导入时缺失的工作流造成来源歧义时停止，用户指定经过核对的 SHA 后才初始化", t => {
  const f = fixture(t, true);
  const source = f.git(f.upstream, "rev-parse", "HEAD");
  writeFileSync(join(f.upstream, ".github/workflows/check.yml"), "name: updated upstream workflow\n");
  f.commit(f.upstream, "workflow-only update");
  const before = f.refs();
  const pending = f.run({ TEST_EXISTING_PR: "https://github.com/synthetic/deployment/pull/8" });
  assert.equal(pending.status, 0, pending.stderr);
  assert.equal(f.refs(), before);
  assert.match(readFileSync(f.summary, "utf8"), /pull\/8/);
  const ambiguous = f.run();
  assert.equal(ambiguous.status, 1);
  assert.match(ambiguous.stderr, /无法确定部署版本/);
  assert.equal(f.refs(), before);
  const selected = f.run({ INITIAL_UPSTREAM_COMMIT: source });
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(f.git(f.origin, "show", "sync-upstream/42-1:.github/upstream-base"), source);
  assert.match(f.git(f.origin, "show", "sync-upstream/42-1:.github/workflows/check.yml"), /updated upstream workflow/);
});

test("指定较新的不匹配 SHA 不能把尚未同步的代码冒充已部署版本", t => {
  const f = fixture(t, true);
  const latest = f.advance();
  const before = f.refs();
  const result = f.run({ INITIAL_UPSTREAM_COMMIT: latest });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /所填版本与当前服务不符/);
  assert.equal(f.refs(), before);
});

test("创建 PR 失败时保留同步分支供人工创建 PR，生产分支不变", t => {
  const f = fixture(t);
  f.advance();
  const before = f.git(f.origin, "rev-parse", "production");
  const result = f.run({ TEST_CREATE_FAILURE: "1" });
  assert.equal(result.status, 1);
  assert.equal(f.git(f.origin, "rev-parse", "production"), before);
  assert.equal(f.git(f.origin, "show", "sync-upstream/42-1:version.txt"), "version two");
  assert.match(readFileSync(f.summary, "utf8"), /未能创建更新请求.*sync-upstream\/42-1/);
});

test("工作区有未提交修改时停止并保留修改", t => {
  const f = fixture(t);
  f.advance();
  writeFileSync(join(f.deployed, "version.txt"), "unfinished local edit\n");
  const before = f.refs();
  const result = f.run();
  assert.equal(result.status, 1);
  assert.match(result.stdout, /有尚未保存的修改/);
  assert.equal(f.refs(), before);
  assert.equal(readFileSync(join(f.deployed, "version.txt"), "utf8"), "unfinished local edit\n");
});
