#!/usr/bin/env bash

set -euo pipefail

SRC_ROOT="/mnt/sdb/hjr/PoC/0417PoC_hf"
REF_ROOT="/mnt/sdb/hjr/PoC/0412PoC"
WORK_ROOT="/mnt/sdb/hjr/PoC/0417PoC_hf"
SESSION_NAME="${1:-rewrite_0417_poc_hf}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux not found"
  exit 1
fi

if ! command -v codex >/dev/null 2>&1; then
  echo "codex not found"
  exit 1
fi

if [[ ! -d "$SRC_ROOT" ]]; then
  echo "source root not found: $SRC_ROOT"
  exit 1
fi

if [[ ! -d "$REF_ROOT" ]]; then
  echo "reference root not found: $REF_ROOT"
  exit 1
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "tmux session already exists: $SESSION_NAME"
  echo "attach with: tmux attach -t $SESSION_NAME"
  exit 1
fi

find_reference_markdown() {
  local firmware_name="$1"
  local ref_dir="$REF_ROOT/${firmware_name}.zip"
  local child_dir

  if [[ ! -d "$ref_dir" ]]; then
    return 1
  fi

  while IFS= read -r child_dir; do
    if find "$child_dir" -maxdepth 1 -type f -name '*.md' | grep -q .; then
      find "$child_dir" -maxdepth 1 -type f -name '*.md' | sort | head -n 1
      return 0
    fi
  done < <(find "$ref_dir" -mindepth 1 -maxdepth 1 -type d | sort)

  return 1
}

build_prompt() {
  local firmware_dir="$1"
  local template_md="$2"
  cat <<EOF
请处理固件目录：$firmware_dir

要求：
1. 参考模板 markdown：$template_md
2. 改写当前固件目录下所有二级子目录中的 markdown 文件内容，也就是形如：
   $firmware_dir/*/*.md
3. 目标是让这些 markdown 的整体结构、章节组织、书写风格、字段粒度尽量与模板一致。
4. 必须基于当前各自样本目录里的现有分析材料进行改写，不能把不同漏洞样本的具体结论互相照搬。
5. 不用处理图片；保留或补成图片占位即可，但不要因为缺图而跳过。
6. 只修改当前固件目录下的 markdown 文件，不要改别的固件目录。
7. 完成后输出一段简短总结，说明修改了哪些 markdown 文件。

补充说明：
- 模板只用来参考格式，不用复制其中的具体漏洞内容。
- 如果当前固件目录下某个样本目录没有 markdown，则跳过那个样本目录。
- 请直接在工作区内完成修改。
EOF
}

build_shell_command() {
  local quoted=""
  printf -v quoted '%q ' "$@"
  printf '%s' "$quoted"
}

window_created=0

while IFS= read -r firmware_dir; do
  firmware_name="$(basename "$firmware_dir")"
  window_name="${firmware_name:0:80}"

  if template_md="$(find_reference_markdown "$firmware_name")"; then
    prompt="$(build_prompt "$firmware_dir" "$template_md")"
    cmd_str="$(build_shell_command \
      codex exec \
      --dangerously-bypass-approvals-and-sandbox \
      --skip-git-repo-check \
      -C "$WORK_ROOT" \
      "$prompt" \
    )"
  else
    cmd_str="$(build_shell_command \
      bash -lc \
      "echo 'skip: $firmware_name'; echo 'reason: no same-name reference folder with markdown under $REF_ROOT'; exec bash" \
    )"
  fi

  if [[ "$window_created" -eq 0 ]]; then
    tmux new-session -d -s "$SESSION_NAME" -n "$window_name" "$cmd_str"
    tmux set-option -t "$SESSION_NAME" remain-on-exit on >/dev/null
    window_created=1
  else
    tmux new-window -t "$SESSION_NAME" -n "$window_name" "$cmd_str"
  fi
done < <(find "$SRC_ROOT" -mindepth 1 -maxdepth 1 -type d | sort)

if [[ "$window_created" -eq 0 ]]; then
  echo "no firmware directories found under $SRC_ROOT"
  exit 1
fi

echo "tmux session created: $SESSION_NAME"
echo "attach with: tmux attach -t $SESSION_NAME"
