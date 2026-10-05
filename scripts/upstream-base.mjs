import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import ts from "typescript";

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
}

function tree(ref) {
  return new Map(git("ls-tree", "-rz", ref).split("\0").filter(Boolean).map(entry => {
    const separator = entry.indexOf("\t");
    return [entry.slice(separator + 1), entry.slice(0, separator)];
  }));
}

function normalizedConfig(ref, path) {
  const parsed = ts.parseConfigFileTextToJson(path, git("show", `${ref}:${path}`));
  if (parsed.error) throw new Error("无法读取部署配置，请联系维护者并附上本次运行记录。");
  const config = parsed.config;
  // Cloudflare 可以重命名包、Worker 和数据库，并填写实例的资源 ID、变量值。
  delete config.name;
  if (path === "wrangler.jsonc") {
    delete config.account_id;
    for (const database of config.d1_databases ?? []) {
      delete database.database_id;
      delete database.database_name;
    }
    for (const key of Object.keys(config.vars ?? {})) config.vars[key] = null;
  }
  return config;
}

function matchesImport(imported, importedTree, candidate) {
  const sourceTree = tree(candidate);
  // 只允许平台删除工作流；导入时已存在的工作流仍必须匹配。
  for (const path of sourceTree.keys()) {
    if (path.startsWith(".github/workflows/") && !importedTree.has(path)) sourceTree.delete(path);
  }
  if (sourceTree.size !== importedTree.size) return false;
  for (const [path, entry] of importedTree) {
    const sourceEntry = sourceTree.get(path);
    if (sourceEntry === entry) continue;
    if (!sourceEntry || entry.split(" ")[0] !== sourceEntry.split(" ")[0]) return false;
    if (path !== "package.json" && path !== "wrangler.jsonc") return false;
    if (!isDeepStrictEqual(normalizedConfig(imported, path), normalizedConfig(candidate, path))) return false;
  }
  return true;
}

function findBase(requested) {
  const roots = git("rev-list", "--max-parents=0", "HEAD").split("\n");
  if (roots.length !== 1) throw new Error("无法识别部署版本，请联系维护者并附上本次运行记录。");
  const imported = roots[0];
  const importedTree = tree(imported);
  if (requested) {
    if (!/^[a-f0-9]{40}$/i.test(requested)) throw new Error("部署版本填写有误，请重新复制完整版本号后重试。");
    const reachable = spawnSync("git", ["merge-base", "--is-ancestor", requested, "refs/remotes/upstream/main"]);
    if (reachable.status !== 0 || !matchesImport(imported, importedTree, requested)) {
      throw new Error("所填版本与当前服务不符，请核对首次部署时使用的版本后重试。");
    }
    return requested;
  }

  // 同一文件树的重复提交等价；不同源文件树不能仅凭导入时间猜测。
  const matches = new Map();
  for (const candidate of git("rev-list", "--first-parent", "refs/remotes/upstream/main").split("\n")) {
    if (matchesImport(imported, importedTree, candidate)) {
      const sourceTree = git("rev-parse", `${candidate}^{tree}`);
      if (!matches.has(sourceTree)) matches.set(sourceTree, candidate);
    }
  }
  if (matches.size === 1) return matches.values().next().value;
  if (matches.size === 0) throw new Error("找不到对应的部署版本，请联系维护者并附上本次运行记录。");
  throw new Error("无法确定部署版本，请在重新运行时填写首次部署使用的版本号。");
}

function initializeBase(base) {
  if (git("status", "--porcelain")) throw new Error("有尚未保存的修改，请先提交后重试。");
  if (spawnSync("git", ["merge-base", "HEAD", "refs/remotes/upstream/main"]).status === 0) {
    throw new Error("服务已准备好更新，请直接运行“更新服务”。");
  }
  // 源快照已核对：先保留实例当前文件，再恢复平台省略、用户从未触及的工作流。
  git("merge", "--strategy=ours", "--allow-unrelated-histories", "--no-ff", "--no-commit", base);
  for (const path of tree(base).keys()) {
    if (path.startsWith(".github/workflows/") && !existsSync(path) && !git("log", "-1", "--format=%H", "HEAD", "--", path)) {
      git("restore", `--source=${base}`, "--staged", "--worktree", "--", path);
    }
  }
  mkdirSync(".github", { recursive: true });
  writeFileSync(".github/upstream-base", `${base}\n`);
  git("add", ".github/upstream-base");
  git("commit", "-m", `chore: 初始化上游来源 ${base}`);
}

try {
  const [mode, source] = process.argv.slice(2);
  if ((mode && mode !== "--initialize") || process.argv.length > 4) throw new Error("更新命令有误，请通过 mise run sync:init 运行。");
  const base = findBase(source ?? process.env.INITIAL_UPSTREAM_COMMIT ?? "");
  if (mode === "--initialize") initializeBase(base);
  console.log(base);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
