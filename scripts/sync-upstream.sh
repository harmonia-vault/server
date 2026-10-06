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

existing_pr=$(gh pr list --repo "$GITHUB_REPOSITORY" --base "$GITHUB_REF_NAME" \
  --state open --limit 100 --json headRefName,url \
  --jq '[.[] | select(.headRefName | startswith("sync-upstream/"))][0].url // empty')
if [[ -n "$existing_pr" ]]; then
  printf '已有[更新请求](%s)，请先打开处理。\n' "$existing_pr" >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

if ! base=$(node "$base_helper"); then
  echo '更新未完成，请查看“创建更新请求”步骤中的提示后重试。' >> "$GITHUB_STEP_SUMMARY"
  exit 1
fi
upstream_commit=$(git rev-parse refs/remotes/upstream/main)
deployment_commit=$(git rev-parse HEAD)
scratch=$(mktemp -d "$RUNNER_TEMP/harmonia-sync.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git config core.hooksPath /dev/null

# 两个合并快照都使用调用方的工作流和版本记录，避免工作流差异或冲突参与合并。
# 独立索引只写 Git 对象，不修改用户检出的文件。
snapshot() {
  GIT_INDEX_FILE="$scratch/index" git read-tree "$1"
  GIT_INDEX_FILE="$scratch/index" git rm -r --cached --force --quiet --ignore-unmatch -- .github/workflows .github/upstream-base
  git ls-tree -rz "$deployment_commit" -- .github/workflows .github/upstream-base |
    GIT_INDEX_FILE="$scratch/index" git update-index -z --index-info
  GIT_INDEX_FILE="$scratch/index" git write-tree
}

base_tree=$(snapshot "$base")
upstream_tree=$(snapshot "$upstream_commit")
if [[ "$base_tree" == "$upstream_tree" ]] && {
  git cat-file -e HEAD:.github/upstream-base 2>/dev/null || git merge-base HEAD "$upstream_commit" >/dev/null;
}; then
  echo '服务代码已是最新版本。' >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

base_snapshot=$(git commit-tree "$base_tree" -m 'sync merge base')
upstream_snapshot=$(git commit-tree "$upstream_tree" -m 'sync upstream snapshot')
merge_status=0
git merge-tree --write-tree --name-only --merge-base="$base_snapshot" "$deployment_commit" "$upstream_snapshot" \
  > "$scratch/merge-result" || merge_status=$?
if [[ "$merge_status" != 0 ]]; then
  if [[ "$merge_status" == 1 ]]; then
    {
      echo '更新与自己的修改发生冲突，请联系维护者并附上本次运行记录。'
      tail -n +2 "$scratch/merge-result"
    } >> "$GITHUB_STEP_SUMMARY"
  else
    echo '合并更新失败，请联系维护者并附上本次运行记录。' >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 1
fi

GIT_INDEX_FILE="$scratch/index" git read-tree "$(head -n 1 "$scratch/merge-result")"
state_blob=$(printf '%s\n' "$upstream_commit" | git hash-object -w --stdin)
GIT_INDEX_FILE="$scratch/index" git update-index --add --cacheinfo 100644 "$state_blob" .github/upstream-base
update_tree=$(GIT_INDEX_FILE="$scratch/index" git write-tree)
if ! git diff --quiet "$deployment_commit" "$update_tree" -- .github/workflows; then
  echo '::error::更新会改动工作流，已停止。请联系维护者并附上本次运行记录。'
  exit 1
fi

# 只推送以部署版本为父提交的结果，不引入包含工作流变更的上游提交历史。
# 独立保存源版本，使普通合并和 squash 后的下一次更新使用同一三方合并基线。
update_commit=$(git commit-tree "$update_tree" -p "$deployment_commit" -m "chore: 同步上游 ${upstream_commit:0:12}")
sync_branch="sync-upstream/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
git update-ref "refs/heads/$sync_branch" "$update_commit"
if ! git push origin "refs/heads/$sync_branch:refs/heads/$sync_branch"; then
  echo '推送更新失败，请检查仓库的 Actions 写入权限后重试。' >> "$GITHUB_STEP_SUMMARY"
  exit 1
fi

cat > "$scratch/pr-body" <<'EOF'
检查服务配置后，合并此 Pull Request。

合并后，在 Cloudflare 的 **Deployments** 中确认部署完成。
EOF
if ! pr_url=$(gh pr create --repo "$GITHUB_REPOSITORY" --base "$GITHUB_REF_NAME" \
  --head "$sync_branch" --title '更新服务' --body-file "$scratch/pr-body"); then
  printf '未能创建更新请求，请检查[Actions 设置](https://github.com/harmonia-vault/server#actions-更新)，再[手动创建更新请求](https://github.com/%s/compare/%s...%s?expand=1)。\n' \
    "$GITHUB_REPOSITORY" "$GITHUB_REF_NAME" "$sync_branch" >> "$GITHUB_STEP_SUMMARY"
  exit 1
fi
printf '已生成[更新请求](%s)，请打开处理。\n' "$pr_url" >> "$GITHUB_STEP_SUMMARY"
