#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_NAME="codex_dedup_firmware"
REPLACE_SESSION=0
WAIT_INTERVAL=5
TOBE_CHECK=""
FINISH_ROOT=""
PROMPT_FILE=""
declare -a REQUESTED_FIRMWARES=()

usage() {
  cat <<'EOF'
Usage: checkDedupFirmware.sh --tobecheck DIR --finish DIR [options]

检查待去重固件目录与已完成报告目录的一级固件名是否匹配，为匹配上的固件生成
needCheckDedup.json，并通过 tmux + codex 批量生成 tobedeleted.json，最后删除已
经报告过的漏洞子目录。

Options:
  --tobecheck DIR      待检查固件根目录，例如 /mnt/sdb/hjr/PoC/0417PoC_hf
  --finish DIR         已完成报告根目录，例如 /mnt/sdb/hjr/PoC/0412PoC
  --firmware NAME      只运行指定固件；可重复传入多次
  --session NAME       tmux session 名称，默认 codex_dedup_firmware
  --prompt FILE        提示词模板，默认 <tobecheck>/AGENT_DEDUP_FINISH_VUL.md
  --replace-session    如 tmux session 已存在则先删除再重新创建
  -h, --help           显示帮助
EOF
}

trim_trailing_slash() {
  local value="$1"
  while [[ "$value" != "/" && "$value" == */ ]]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
}

resolve_dir() {
  local input
  input="$(trim_trailing_slash "$1")"
  if [[ ! -d "$input" ]]; then
    echo "[ERROR] directory not found: $input" >&2
    exit 2
  fi
  (
    cd "$input"
    pwd
  )
}

resolve_file() {
  local input="$1"
  if [[ ! -f "$input" ]]; then
    echo "[ERROR] file not found: $input" >&2
    exit 2
  fi
  (
    cd "$(dirname "$input")"
    printf '%s/%s\n' "$(pwd)" "$(basename "$input")"
  )
}

append_firmware_arg() {
  local raw="$1"
  local item trimmed
  local -a items=()
  IFS=',' read -r -a items <<< "$raw"
  for item in "${items[@]}"; do
    trimmed="${item#"${item%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -n "$trimmed" ]] || continue
    REQUESTED_FIRMWARES+=("$trimmed")
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tobecheck)
      TOBE_CHECK="$2"
      shift 2
      ;;
    --finish)
      FINISH_ROOT="$2"
      shift 2
      ;;
    --firmware)
      append_firmware_arg "$2"
      shift 2
      ;;
    --session)
      SESSION_NAME="$2"
      shift 2
      ;;
    --prompt)
      PROMPT_FILE="$2"
      shift 2
      ;;
    --replace-session)
      REPLACE_SESSION=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      echo "[ERROR] unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      echo "[ERROR] unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TOBE_CHECK" || -z "$FINISH_ROOT" ]]; then
  echo "[ERROR] --tobecheck and --finish are required" >&2
  usage >&2
  exit 2
fi

for required_cmd in python3 codex tmux; do
  if ! command -v "$required_cmd" >/dev/null 2>&1; then
    echo "[ERROR] missing required command: $required_cmd" >&2
    exit 2
  fi
done

TOBE_CHECK="$(resolve_dir "$TOBE_CHECK")"
FINISH_ROOT="$(resolve_dir "$FINISH_ROOT")"

if [[ -z "$PROMPT_FILE" ]]; then
  PROMPT_FILE="$TOBE_CHECK/AGENT_DEDUP_FINISH_VUL.md"
fi
PROMPT_FILE="$(resolve_file "$PROMPT_FILE")"

NEED_CHECK_JSON="$TOBE_CHECK/needCheckDedup.json"

build_need_check_json() {
  python3 - "$TOBE_CHECK" "$FINISH_ROOT" "$NEED_CHECK_JSON" "${REQUESTED_FIRMWARES[@]}" <<'PY'
import json
import os
import sys

tobe_root, finish_root, output_path, *requested = sys.argv[1:]

ignored_names = {"__pycache__"}

def list_top_dirs(root):
    names = []
    for entry in os.listdir(root):
        full_path = os.path.join(root, entry)
        if not os.path.isdir(full_path):
            continue
        if entry.startswith(".") or entry in ignored_names:
            continue
        names.append(entry)
    return sorted(names)

finish_dirs = list_top_dirs(finish_root)
finish_lookup = set(finish_dirs)
normalized_finish_lookup = set()
for name in finish_dirs:
    normalized_finish_lookup.add(name)
    if name.endswith(".zip"):
        normalized_finish_lookup.add(name[:-4])

requested_lookup = set()
for name in requested:
    requested_lookup.add(name)
    if name.endswith(".zip"):
        requested_lookup.add(name[:-4])
    else:
        requested_lookup.add(f"{name}.zip")

matched_paths = []
seen_requested = set()
for name in list_top_dirs(tobe_root):
    normalized_name = name[:-4] if name.endswith(".zip") else name
    if requested_lookup and name not in requested_lookup and normalized_name not in requested_lookup:
        continue
    if name in finish_lookup or normalized_name in normalized_finish_lookup:
        matched_paths.append(os.path.realpath(os.path.join(tobe_root, name)))
        seen_requested.add(name)
        seen_requested.add(normalized_name)

if requested_lookup:
    missing = []
    for name in requested:
        normalized_name = name[:-4] if name.endswith(".zip") else name
        if name not in seen_requested and normalized_name not in seen_requested:
            missing.append(name)
    if missing:
        raise SystemExit(
            "requested firmware not found in overlapping tobecheck/finish roots: "
            + ", ".join(missing)
        )

with open(output_path, "w", encoding="utf-8") as fp:
    json.dump(matched_paths, fp, ensure_ascii=False, indent=2)
    fp.write("\n")
PY
}

load_need_check_dirs() {
  python3 - "$NEED_CHECK_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fp:
    data = json.load(fp)

if not isinstance(data, list):
    raise SystemExit("needCheckDedup.json must be a JSON array")

for item in data:
    if not isinstance(item, str):
        raise SystemExit("needCheckDedup.json must only contain strings")
    print(item)
PY
}

resolve_finish_firmware_dir() {
  local firmware_name="$1"
  local -a candidates=(
    "$FINISH_ROOT/$firmware_name"
    "$FINISH_ROOT/${firmware_name}.zip"
  )

  if [[ "$firmware_name" == *.zip ]]; then
    candidates+=("$FINISH_ROOT/${firmware_name%.zip}")
  fi

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      (
        cd "$candidate"
        pwd
      )
      return 0
    fi
  done

  return 1
}

build_prompt() {
  local firmware_dir="$1"
  local finish_firmware_dir="$2"
  local output_json="$firmware_dir/tobedeleted.json"

  cat <<EOF
请严格按照模板文件 $PROMPT_FILE 的要求处理当前固件。

当前待检查固件目录：
$firmware_dir

对应的已完成漏洞报告目录：
$finish_firmware_dir

结果输出文件：
$output_json

额外要求：
1. 只处理当前这个固件目录，不要修改其他固件目录。
2. 必须先通读当前固件目录下每个漏洞子目录中的 markdown 报告，再通读已完成目录下同固件已有报告的 markdown。
3. 判断“是否已报告”时，依据漏洞位置、触发路由/接口、危险函数、关键参数、根因与利用方式综合判断，不能仅按目录名或 crash 文件名做字符串匹配。
4. 将确认已被已完成目录覆盖的漏洞子目录名写入 $output_json，格式必须是 JSON 字符串数组。
5. 如果没有任何待删除目录，也必须写入空数组 []。
6. 除了更新 $output_json 以及为完成任务所必需的极少量临时读取，不要改动其他文件内容。
EOF
}

build_window_command() {
  local firmware_dir="$1"
  local finish_firmware_dir="$2"
  local prompt
  prompt="$(build_prompt "$firmware_dir" "$finish_firmware_dir")"

  local status_file="$firmware_dir/.dedup_codex_status"
  local -a codex_args=(
    codex
    exec
    --dangerously-bypass-approvals-and-sandbox
    --skip-git-repo-check
    -C "$TOBE_CHECK"
    "$prompt"
  )
  local codex_cmd
  printf -v codex_cmd '%q ' "${codex_args[@]}"

  local worker_cmd
  worker_cmd="$(cat <<EOF
set -uo pipefail
rm -f $(printf '%q' "$status_file")
$codex_cmd
status=\$?
printf '%s\n' "\$status" > $(printf '%q' "$status_file")
exit \$status
EOF
)"

  local shell_cmd
  printf -v shell_cmd 'bash -lc %q' "$worker_cmd"
  printf '%s\n' "$shell_cmd"
}

wait_for_tmux_session() {
  echo "[INFO] waiting for tmux session to finish: $SESSION_NAME"
  while tmux has-session -t "$SESSION_NAME" 2>/dev/null; do
    sleep "$WAIT_INTERVAL"
  done
}

validate_tobedeleted_jsons() {
  local missing=0
  local firmware_dir
  for firmware_dir in "${FIRMWARE_DIRS[@]}"; do
    if [[ ! -f "$firmware_dir/tobedeleted.json" ]]; then
      echo "[ERROR] missing tobedeleted.json: $firmware_dir/tobedeleted.json" >&2
      if [[ -f "$firmware_dir/.dedup_codex_status" ]]; then
        echo "[ERROR] codex exit status: $(<"$firmware_dir/.dedup_codex_status")" >&2
      fi
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "[ERROR] not all tobedeleted.json files were generated; skip deletion" >&2
    exit 1
  fi
}

collect_delete_targets() {
  local firmware_dir="$1"
  local tobedeleted_json="$firmware_dir/tobedeleted.json"
  python3 - "$firmware_dir" "$tobedeleted_json" <<'PY'
import json
import os
import sys

firmware_dir, tobedeleted_json = sys.argv[1:3]
firmware_real = os.path.realpath(firmware_dir)

with open(tobedeleted_json, "r", encoding="utf-8") as fp:
    data = json.load(fp)

if not isinstance(data, list):
    raise SystemExit(f"{tobedeleted_json} must be a JSON array")

for item in data:
    if not isinstance(item, str):
        raise SystemExit(f"{tobedeleted_json} contains a non-string entry")
    if not item or item in {".", ".."} or "/" in item:
        raise SystemExit(f"unsafe directory name in {tobedeleted_json}: {item!r}")
    target = os.path.realpath(os.path.join(firmware_real, item))
    if os.path.dirname(target) != firmware_real:
        raise SystemExit(f"unsafe delete target in {tobedeleted_json}: {item!r}")
    if os.path.isdir(target):
        sys.stdout.write(target)
        sys.stdout.write("\0")
PY
}

apply_deletions() {
  local firmware_dir
  local delete_count=0

  for firmware_dir in "${FIRMWARE_DIRS[@]}"; do
    while IFS= read -r -d '' delete_path; do
      rm -rf -- "$delete_path"
      echo "[INFO] deleted duplicate vulnerability directory: $delete_path"
      delete_count=$((delete_count + 1))
    done < <(collect_delete_targets "$firmware_dir")
  done

  echo "[INFO] deleted duplicate directories: $delete_count"
}

build_need_check_json

mapfile -t FIRMWARE_DIRS < <(load_need_check_dirs)

echo "[INFO] needCheckDedup.json written to: $NEED_CHECK_JSON"
echo "[INFO] matched firmware count: ${#FIRMWARE_DIRS[@]}"

if [[ "${#FIRMWARE_DIRS[@]}" -eq 0 ]]; then
  echo "[INFO] no overlapping firmware directories found; nothing to do"
  exit 0
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  if [[ "$REPLACE_SESSION" -eq 1 ]]; then
    echo "[INFO] replacing existing tmux session: $SESSION_NAME"
    tmux kill-session -t "$SESSION_NAME"
  else
    echo "[ERROR] tmux session already exists: $SESSION_NAME" >&2
    echo "        rerun with --replace-session or use --session with a new name" >&2
    exit 2
  fi
fi

declare -a FINISH_FIRMWARE_DIRS=()
for firmware_dir in "${FIRMWARE_DIRS[@]}"; do
  firmware_name="$(basename "$firmware_dir")"
  if ! finish_firmware_dir="$(resolve_finish_firmware_dir "$firmware_name")"; then
    echo "[ERROR] matched firmware missing in finish root: $firmware_name" >&2
    exit 1
  fi
  FINISH_FIRMWARE_DIRS+=("$finish_firmware_dir")
done

first_firmware="${FIRMWARE_DIRS[0]}"
first_finish="${FINISH_FIRMWARE_DIRS[0]}"
first_name="$(basename "$first_firmware")"
first_cmd="$(build_window_command "$first_firmware" "$first_finish")"
tmux new-session -d -s "$SESSION_NAME" -n "${first_name:0:80}" "$first_cmd"

for ((i = 1; i < ${#FIRMWARE_DIRS[@]}; i++)); do
  firmware_dir="${FIRMWARE_DIRS[$i]}"
  firmware_name="$(basename "$firmware_dir")"
  finish_firmware_dir="${FINISH_FIRMWARE_DIRS[$i]}"
  window_cmd="$(build_window_command "$firmware_dir" "$finish_firmware_dir")"
  tmux new-window -t "$SESSION_NAME:" -n "${firmware_name:0:80}" "$window_cmd"
done

echo "[INFO] started tmux session: $SESSION_NAME"
echo "[INFO] attach with: tmux attach -t $SESSION_NAME"

wait_for_tmux_session
validate_tobedeleted_jsons
apply_deletions

echo "[INFO] dedup finished"
