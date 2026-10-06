import { execFileSync, spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import ts from "typescript";

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
}

function serviceTree(ref) {
  const files = new Map();
  for (const entry of git("ls-tree", "-rz", ref).split("\0")) {
    if (!entry) continue;
    const separator = entry.indexOf("\t");
    const path = entry.slice(separator + 1);
    if (!path.startsWith(".github/workflows/")) files.set(path, entry.slice(0, separator));
  }
  return files;
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
  const sourceTree = serviceTree(candidate);
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
  const recorded = spawnSync("git", ["show", "HEAD:.github/upstream-base"], { encoding: "utf8" });
  if (recorded.status === 0) {
    const base = recorded.stdout.trim();
    if (!/^[a-f0-9]{40}$/i.test(base) || spawnSync("git", ["merge-base", "--is-ancestor", base, "refs/remotes/upstream/main"]).status !== 0) {
      throw new Error("无法读取上次更新的版本，请联系维护者并附上本次运行记录。");
    }
    return base;
  }
  const common = spawnSync("git", ["merge-base", "HEAD", "refs/remotes/upstream/main"], { encoding: "utf8" });
  if (common.status === 0) return common.stdout.trim();

  const roots = git("rev-list", "--max-parents=0", "HEAD").split("\n");
  if (roots.length !== 1) throw new Error("无法识别部署版本，请联系维护者并附上本次运行记录。");
  const imported = roots[0];
  const importedTree = serviceTree(imported);
  if (requested) {
    if (!/^[a-f0-9]{40}$/i.test(requested)) throw new Error("部署版本填写有误，请重新复制完整版本号后重试。");
    const reachable = spawnSync("git", ["merge-base", "--is-ancestor", requested, "refs/remotes/upstream/main"]);
    if (reachable.status !== 0 || !matchesImport(imported, importedTree, requested)) {
      throw new Error("所填版本与当前服务不符，请核对首次部署时使用的版本后重试。");
    }
    return requested;
  }

  // 工作流不参与同步；仅工作流不同的版本拥有相同的服务合并基线。
  const matches = new Map();
  for (const candidate of git("rev-list", "--first-parent", "refs/remotes/upstream/main").split("\n")) {
    if (matchesImport(imported, importedTree, candidate)) {
      const snapshot = JSON.stringify([...serviceTree(candidate)]);
      if (!matches.has(snapshot)) matches.set(snapshot, candidate);
    }
  }
  if (matches.size === 1) return matches.values().next().value;
  if (matches.size === 0) throw new Error("找不到对应的部署版本，请联系维护者并附上本次运行记录。");
  throw new Error("无法确定部署版本，请在重新运行时填写首次部署使用的版本号。");
}

try {
  console.log(findBase(process.env.INITIAL_UPSTREAM_COMMIT ?? ""));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
