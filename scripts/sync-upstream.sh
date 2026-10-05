#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_REF_NAME:?}"
: "${GITHUB_RUN_ID:?}"
: "${GITHUB_RUN_ATTEMPT:?}"
: "${GITHUB_STEP_SUMMARY:?}"
: "${RUNNER_TEMP:?}"
base_helper=${1:?缺少更新工具，请通过 mise run sync:upstream 运行}

if [[ -n "$(git status --porcelain)" ]]; then
  echo '::error::有尚未保存的修改，请先提交后重试。'
  exit 1
fi

upstream_commit=$(git rev-parse refs/remotes/upstream/main)
if git merge-base --is-ancestor "$upstream_commit" HEAD; then
  echo '服务代码已是最新版本。' >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

existing_pr=$(gh pr list --repo "$GITHUB_REPOSITORY" --base "$GITHUB_REF_NAME" \
  --state open --limit 100 --json headRefName,url \
  --jq '[.[] | select(.headRefName | startswith("sync-upstream/"))][0].url // empty')
if [[ -n "$existing_pr" ]]; then
  printf '已有[更新请求](%s)，请先打开处理。\n' \
    "$existing_pr" >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

initial_base=''
if ! git merge-base HEAD "$upstream_commit" > /dev/null; then
  # 只对与初始导入快照匹配的上游版本建立关系，不把当前最新版本冒充部署来源。
  if ! initial_base=$(node "$base_helper"); then
    echo '更新未完成，请查看“创建更新请求”步骤中的提示后重试。' >> "$GITHUB_STEP_SUMMARY"
    exit 1
  fi
fi

sync_branch="sync-upstream/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git config core.hooksPath /dev/null
git switch -c "$sync_branch"

if [[ -n "$initial_base" ]]; then
  node "$base_helper" --initialize "$initial_base" > /dev/null
fi

# 三方合并保留部署仓库的修改，并纳入上游新增的绑定和迁移；冲突时不选边覆盖。
if ! git merge --no-ff --no-edit -m "chore: 同步上游 ${upstream_commit:0:12}" "$upstream_commit"; then
  {
    echo '更新与自己的修改发生冲突，请联系维护者并附上本次运行记录。'
    git diff --name-only --diff-filter=U
  } >> "$GITHUB_STEP_SUMMARY"
  if git rev-parse --verify -q MERGE_HEAD > /dev/null; then
    git merge --abort
  fi
  exit 1
fi

git push origin "HEAD:refs/heads/$sync_branch"

body_file=$(mktemp "$RUNNER_TEMP/harmonia-sync-pr.XXXXXX")
trap 'rm -f "$body_file"' EXIT
cat > "$body_file" <<EOF
检查服务配置后，点击 **Create a merge commit** 应用本次更新。

合并后，在 Cloudflare 的 **Deployments** 中确认部署完成。
EOF

if ! pr_url=$(gh pr create --repo "$GITHUB_REPOSITORY" --base "$GITHUB_REF_NAME" \
  --head "$sync_branch" --title "更新服务" --body-file "$body_file"); then
  printf '未能创建更新请求，请在自己的仓库将 %s 提交到 %s，手动创建更新请求。\n' \
    "$sync_branch" "$GITHUB_REF_NAME" >> "$GITHUB_STEP_SUMMARY"
  exit 1
fi

printf '已生成[更新请求](%s)，请打开处理。\n' \
  "$pr_url" >> "$GITHUB_STEP_SUMMARY"
