#!/usr/bin/env python3
"""
prompt-review スキル用 公式エクスポートデータ収集スクリプト

ChatGPT および Gemini のウェブアプリ版公式エクスポートファイル（ZIP）を解析し、
collect.py と完全に同一の JSON 構造を stdout に出力する。

使い方:
    python collect_export.py --input /path/to/chatgpt-export.zip --service chatgpt
    python collect_export.py --input /path/to/takeout.zip --service gemini
    python collect_export.py --chatgpt /path/to/chatgpt.zip --gemini /path/to/takeout.zip
    python collect_export.py --input /path/to/chatgpt.zip --service chatgpt --days 30
    python collect_export.py --input /path/to/chatgpt.zip --service chatgpt --days 0
"""

import argparse
import json
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone


# クレデンシャル・シークレット検出パターン（collect.py からコピー）
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+', "API Key"),
    (r'(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*\S+', "Secret/Token/Password"),
    (r'(?i)(access[_-]?key|secret[_-]?key)\s*[:=]\s*\S+', "Access Key"),
    (r'(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*', "Bearer Token"),
    (r'sk-[A-Za-z0-9]{20,}', "OpenAI API Key"),
    (r'sk-ant-[A-Za-z0-9\-]{20,}', "Anthropic API Key"),
    (r'ghp_[A-Za-z0-9]{36,}', "GitHub Personal Access Token"),
    (r'gho_[A-Za-z0-9]{36,}', "GitHub OAuth Token"),
    (r'AIza[A-Za-z0-9\-_]{35}', "Google API Key"),
    (r'(?i)aws[_-]?(access|secret)[_-]?key\S*\s*[:=]\s*\S+', "AWS Key"),
    (r'xox[bpras]-[A-Za-z0-9\-]{10,}', "Slack Token"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "Private Key"),
    (r'(?i)(mongodb(\+srv)?://)\S+:\S+@', "MongoDB Connection String"),
    (r'(?i)(postgres(ql)?://)\S+:\S+@', "PostgreSQL Connection String"),
    (r'(?i)(mysql://)\S+:\S+@', "MySQL Connection String"),
]
_compiled_patterns = [(re.compile(p), label) for p, label in SECRET_PATTERNS]


def scan_secrets(text: str) -> list[dict]:
    """テキスト内のクレデンシャル・シークレットを検出する（collect.py からコピー）"""
    findings = []
    for pattern, label in _compiled_patterns:
        for match in pattern.finditer(text):
            matched = match.group()
            if len(matched) > 16:
                masked = matched[:8] + "***" + matched[-4:]
            else:
                masked = matched[:4] + "***"
            findings.append({
                "type": label,
                "masked_value": masked,
            })
    return findings


def ts_to_iso(ts_ms: int) -> str:
    """Unix epoch ミリ秒をISO 8601文字列に変換（collect.py からコピー）"""
    try:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (OSError, ValueError):
        return "unknown"


def iso_to_ms(iso_str: str) -> int | None:
    """ISO 8601タイムスタンプをUnix epoch ミリ秒に変換（collect.py からコピー）"""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return None


def sanitize_text(text: str) -> str:
    """サロゲート文字等のJSON非互換文字を除去する（collect.py からコピー）"""
    return text.encode("utf-8", errors="replace").decode("utf-8")


def find_file_in_zip(zf: zipfile.ZipFile, suffix: str) -> str | None:
    """ZIP 内からサフィックスにマッチするファイルを探す"""
    for name in zf.namelist():
        if name.endswith(suffix):
            return name
    return None


def collect_chatgpt(zip_path: str, cutoff_ms: int | None) -> dict:
    """ChatGPT エクスポート ZIP を解析してメッセージを収集する"""
    result = {"tool": "ChatGPT", "status": "未検出", "messages": [], "period": ""}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            target = find_file_in_zip(zf, "conversations.json")
            if target is None:
                return result

            with zf.open(target) as f:
                data = json.load(f)
    except (zipfile.BadZipFile, OSError, json.JSONDecodeError) as e:
        result["status"] = "フォーマット不明"
        result["detail"] = str(e)
        return result

    if not isinstance(data, list):
        result["status"] = "フォーマット不明"
        result["detail"] = f"conversations.json のルートが配列ではありません: {type(data).__name__}"
        return result

    messages = []

    for conversation in data:
        if not isinstance(conversation, dict):
            continue

        title = conversation.get("title", "") or ""
        project = sanitize_text(title[:30])
        mapping = conversation.get("mapping", {})
        if not isinstance(mapping, dict):
            continue

        for node_id, node in mapping.items():
            if not isinstance(node, dict):
                continue

            message = node.get("message")
            if not message or not isinstance(message, dict):
                continue

            author = message.get("author", {})
            if not isinstance(author, dict):
                continue
            if author.get("role") != "user":
                continue

            content = message.get("content", {})
            if not isinstance(content, dict):
                continue

            # parts を文字列要素のみ連結（content_type 不問）
            parts = content.get("parts", [])
            text_parts = [p for p in parts if isinstance(p, str)]
            text = sanitize_text("".join(text_parts).strip())

            if not text:
                continue

            # タイムスタンプ: Unix epoch 秒（浮動小数点）→ ミリ秒
            create_time = message.get("create_time")
            if create_time is not None:
                ts_ms = int(float(create_time) * 1000)
            else:
                ts_ms = 0

            if cutoff_ms and ts_ms and ts_ms < cutoff_ms:
                continue

            messages.append({
                "text": text[:500],
                "timestamp": ts_to_iso(ts_ms) if ts_ms else "unknown",
                "timestamp_ms": ts_ms,
                "project": project,
            })

    if messages:
        result["status"] = "検出"
        result["messages"] = messages
        timestamps = [m["timestamp"] for m in messages if m["timestamp"] != "unknown"]
        if timestamps:
            result["period"] = f"{min(timestamps)} 〜 {max(timestamps)}"

    return result


def collect_gemini(zip_path: str, cutoff_ms: int | None) -> dict:
    """Gemini Takeout ZIP を解析してメッセージを収集する"""
    result = {"tool": "Gemini", "status": "未検出", "messages": [], "period": ""}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()

            # .json ファイルを探索（Gemini アクティビティファイルを優先）
            json_files = [n for n in names if n.endswith(".json")]
            if not json_files:
                result["status"] = "フォーマット不明"
                result["detail"] = f"ZIP 内に .json ファイルが見つかりません。ファイル一覧: {names[:20]}"
                return result

            # "Gemini" を含むファイルを優先、なければ最初の .json を使用
            gemini_files = [n for n in json_files if "Gemini" in n or "gemini" in n]
            target_files = gemini_files if gemini_files else json_files

            all_messages = []

            for target in target_files:
                try:
                    with zf.open(target) as f:
                        data = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                parsed = _parse_gemini_data(data, cutoff_ms)
                if parsed is not None:
                    all_messages.extend(parsed)

    except (zipfile.BadZipFile, OSError) as e:
        result["status"] = "フォーマット不明"
        result["detail"] = str(e)
        return result

    if all_messages:
        result["status"] = "検出"
        result["messages"] = all_messages
        timestamps = [m["timestamp"] for m in all_messages if m["timestamp"] != "unknown"]
        if timestamps:
            result["period"] = f"{min(timestamps)} 〜 {max(timestamps)}"
    elif result["status"] == "未検出":
        # ファイルは見つかったが解析できなかった場合
        pass

    return result


def _parse_gemini_data(data, cutoff_ms: int | None) -> list[dict] | None:
    """
    Gemini JSON データをパターン A または B で解析する。
    解析できた場合はメッセージリストを返す。失敗した場合は None を返す。
    """
    if not isinstance(data, list) or len(data) == 0:
        return None

    first = data[0]
    if not isinstance(first, dict):
        return None

    # パターン A 判定: "header" と "title" と "time" を持つ
    if "header" in first and "title" in first and "time" in first:
        return _parse_gemini_pattern_a(data, cutoff_ms)

    # パターン B 判定: "turns" を持つ
    if "turns" in first:
        return _parse_gemini_pattern_b(data, cutoff_ms)

    return None


def _parse_gemini_pattern_a(data: list, cutoff_ms: int | None) -> list[dict]:
    """My Activity 形式（パターン A）を解析する"""
    messages = []

    for entry in data:
        if not isinstance(entry, dict):
            continue

        header = entry.get("header", "")
        if "Gemini" not in str(header):
            continue

        title = entry.get("title", "")
        if not title or not isinstance(title, str):
            continue

        text = sanitize_text(title.strip())
        if not text:
            continue

        time_str = entry.get("time", "")
        ts_ms = iso_to_ms(time_str) if time_str else None

        if cutoff_ms and ts_ms and ts_ms < cutoff_ms:
            continue

        messages.append({
            "text": text[:500],
            "timestamp": ts_to_iso(ts_ms) if ts_ms else "unknown",
            "timestamp_ms": ts_ms or 0,
            "project": "Gemini",
        })

    return messages


def _parse_gemini_pattern_b(data: list, cutoff_ms: int | None) -> list[dict]:
    """会話形式（パターン B）を解析する"""
    messages = []

    for conversation in data:
        if not isinstance(conversation, dict):
            continue

        turns = conversation.get("turns", [])
        if not isinstance(turns, list):
            continue

        for turn in turns:
            if not isinstance(turn, dict):
                continue
            if turn.get("role") != "user":
                continue

            text = sanitize_text(str(turn.get("text", "")).strip())
            if not text:
                continue

            timestamp_str = turn.get("timestamp", "")
            ts_ms = iso_to_ms(timestamp_str) if timestamp_str else None

            if cutoff_ms and ts_ms and ts_ms < cutoff_ms:
                continue

            messages.append({
                "text": text[:500],
                "timestamp": ts_to_iso(ts_ms) if ts_ms else "unknown",
                "timestamp_ms": ts_ms or 0,
                "project": "Gemini",
            })

    return messages


def build_output(sources: list[dict], days: int) -> dict:
    """collect.py と同一構造の出力 JSON を組み立てる"""
    total_messages = sum(len(s["messages"]) for s in sources)
    detected = [s["tool"] for s in sources if s["status"] == "検出"]

    output = {
        "summary": {
            "total_messages": total_messages,
            "detected_tools": detected,
            "filter_days": days,
            "filter_project": None,
            "collected_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        },
        "sources": sources,
    }

    # シークレット検出
    secret_warnings = []
    for source in sources:
        for msg in source["messages"]:
            findings = scan_secrets(msg["text"])
            if findings:
                for f in findings:
                    secret_warnings.append({
                        "tool": source["tool"],
                        "project": msg.get("project", "unknown"),
                        "timestamp": msg.get("timestamp", "unknown"),
                        "type": f["type"],
                        "masked_value": f["masked_value"],
                        "prompt_excerpt": msg["text"][:80].replace("\n", " "),
                    })
    output["secret_warnings"] = secret_warnings

    # プロジェクト別集計
    project_stats = {}
    for source in sources:
        for msg in source["messages"]:
            proj = msg.get("project", "unknown")
            if proj not in project_stats:
                project_stats[proj] = {"count": 0, "tools": set()}
            project_stats[proj]["count"] += 1
            project_stats[proj]["tools"].add(source["tool"])
    output["project_stats"] = {
        k: {"count": v["count"], "tools": list(v["tools"])}
        for k, v in sorted(project_stats.items(), key=lambda x: -x[1]["count"])
    }

    return output


def main():
    parser = argparse.ArgumentParser(
        description="ChatGPT / Gemini エクスポート ZIP を解析して対話履歴を収集する"
    )
    parser.add_argument("--input", type=str, default=None, help="解析する ZIP ファイルのパス")
    parser.add_argument(
        "--service",
        type=str,
        choices=["chatgpt", "gemini"],
        default=None,
        help="サービス名（--input と組み合わせて使用）",
    )
    parser.add_argument("--chatgpt", type=str, default=None, help="ChatGPT エクスポート ZIP のパス")
    parser.add_argument("--gemini", type=str, default=None, help="Gemini Takeout ZIP のパス")
    parser.add_argument(
        "--days",
        type=int,
        default=0,
        help="過去 N 日分に限定（デフォルト: 0 = 全期間）",
    )
    args = parser.parse_args()

    # --input + --service を --chatgpt / --gemini に変換
    chatgpt_path = args.chatgpt
    gemini_path = args.gemini

    if args.input and args.service:
        if args.service == "chatgpt":
            chatgpt_path = chatgpt_path or args.input
        elif args.service == "gemini":
            gemini_path = gemini_path or args.input

    if not chatgpt_path and not gemini_path:
        parser.error("--chatgpt または --gemini（あるいは --input + --service）を指定してください。")

    # カットオフ算出
    cutoff_ms = None
    if args.days and args.days > 0:
        cutoff_dt = datetime.now(tz=timezone.utc) - timedelta(days=args.days)
        cutoff_ms = int(cutoff_dt.timestamp() * 1000)

    sources = []

    if chatgpt_path:
        sources.append(collect_chatgpt(chatgpt_path, cutoff_ms))
    else:
        sources.append({"tool": "ChatGPT", "status": "未検出", "messages": [], "period": ""})

    if gemini_path:
        sources.append(collect_gemini(gemini_path, cutoff_ms))
    else:
        sources.append({"tool": "Gemini", "status": "未検出", "messages": [], "period": ""})

    output = build_output(sources, args.days)

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
