#!/usr/bin/env python3
"""
prompt-review スキル用 ウェブアプリ会話履歴収集スクリプト

Chrome から sessionKey クッキーを手動コピーして --session-key で渡す方式。
出力フォーマットは collect.py / collect_export.py と完全同一。

使い方:
    python collect_web.py --session-key <value>
    python collect_web.py --session-key <value> --days 30
    python collect_web.py --session-key <value> --days 0    # 全期間

sessionKey の取得方法:
    1. Chrome で https://claude.ai を開く
    2. DevTools を開く（F12 / Cmd+Option+I）
    3. Application → Cookies → https://claude.ai
    4. sessionKey の値をコピー
    5. --session-key オプションで渡す
"""

import argparse
import json
import logging
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


# クレデンシャル・シークレット検出パターン（collect_export.py からコピー）
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

_SESSION_KEY_HELP = """\
sessionKey を Chrome から取得してください:
  1. Chrome で https://claude.ai を開く
  2. DevTools を開く（F12 / Cmd+Option+I）
  3. Application → Cookies → https://claude.ai
  4. sessionKey の値をコピー
  5. --session-key オプションで渡す"""


def scan_secrets(text: str) -> list[dict]:
    """テキスト内のクレデンシャル・シークレットを検出する（collect_export.py からコピー）"""
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
    """Unix epoch ミリ秒をISO 8601文字列に変換"""
    try:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (OSError, ValueError):
        return "unknown"


def _iso_to_ms(iso_str: str) -> int | None:
    """ISO 8601タイムスタンプをUnix epoch ミリ秒に変換"""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return None


def _ms_to_display(ts_ms: int | None) -> str:
    """ミリ秒タイムスタンプを表示用文字列に変換"""
    if ts_ms:
        return ts_to_iso(ts_ms)
    return "unknown"


_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
    "Referer": "https://claude.ai/",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}


def _make_client(session_key: str):
    """curl_cffi (優先) または requests のセッションを返す"""
    cookie_header = f"sessionKey={session_key}"
    try:
        from curl_cffi import requests as cffi_requests
        session = cffi_requests.Session(impersonate="chrome124")
        session.headers.update(_BROWSER_HEADERS)
        session.headers["Cookie"] = cookie_header
        logger.debug("[collect_web] HTTP クライアント: curl_cffi (Chrome124 impersonate)")
        return session, "cffi"
    except ImportError:
        import requests as req
        session = req.Session()
        session.headers.update(_BROWSER_HEADERS)
        session.headers["Cookie"] = cookie_header
        logger.debug("[collect_web] HTTP クライアント: requests（Cloudflare でブロックされる場合は curl_cffi を pip install してください）")
        return session, "requests"


def _fetch_org_id(session_key: str) -> str:
    """sessionKey を使って /api/organizations から org_id を取得する"""
    url = "https://claude.ai/api/organizations"
    try:
        session, backend = _make_client(session_key)
        r = session.get(url, timeout=15)
        logger.debug("[collect_web] GET %s → %d", url, r.status_code)
        if r.status_code == 403:
            logger.error(
                "[collect_web] 403 Forbidden（Cloudflare ブロック）。\n"
                "  pip install curl_cffi  でインストールすると回避できます。"
            )
            return ""
        if r.ok:
            data = r.json()
            logger.debug("[collect_web] organizations レスポンス: %s", str(data)[:200])
            if isinstance(data, list) and data:
                return data[0].get("uuid", "")
            if isinstance(data, dict):
                return data.get("uuid", "")
        logger.error("[collect_web] org_id 取得失敗: HTTP %d %s", r.status_code, r.text[:200])
    except Exception as e:
        logger.error("[collect_web] org_id 取得中に例外: %s", e)
    return ""


def _api_get(session, url: str) -> object:
    """セッション GET ラッパー（429 リトライ付き、最大3回、5秒待機）"""
    for attempt in range(3):
        response = session.get(url, timeout=30)
        logger.debug("[collect_web] GET %s → %d", url, response.status_code)
        if response.status_code == 429:
            if attempt < 2:
                logger.warning("[collect_web] 429 Too Many Requests、5秒待機... (%d/3)", attempt + 1)
                time.sleep(5)
                continue
        return response
    return response


def _extract_text(msg: dict) -> str:
    """会話メッセージからテキストを抽出する"""
    # Claude.ai API は text フィールドに直接テキストを返す
    if msg.get("text"):
        return msg["text"]
    content = msg.get("content", [])
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return " ".join(parts)
    return ""


def _fetch_claude_conversations(session, org_id: str, cutoff_ms: int | None) -> list[dict] | None:
    """Claude.ai API から会話履歴を取得する。認証エラー時は None"""
    base = "https://claude.ai"

    r = _api_get(session, f"{base}/api/organizations/{org_id}/chat_conversations")
    if r.status_code in (401, 403):
        logger.error("[collect_web] 会話一覧取得: HTTP %d（未認証）", r.status_code)
        return None  # 未認証シグナル
    if not r.ok:
        logger.error("[collect_web] 会話一覧取得失敗: HTTP %d %s", r.status_code, r.text[:200])
        return []

    try:
        conversations = r.json()
    except Exception as e:
        logger.error("[collect_web] 会話一覧 JSON パース失敗: %s", e)
        return []

    if not isinstance(conversations, list):
        logger.error("[collect_web] 想定外のレスポンス形式: %s", str(conversations)[:200])
        return []

    logger.debug("[collect_web] 会話数: %d", len(conversations))
    messages = []
    for conv in conversations:
        if not isinstance(conv, dict):
            continue

        # updated_at（最終更新）で絞り込み。なければ created_at にフォールバック
        ts_ms = _iso_to_ms(conv.get("updated_at") or conv.get("created_at", ""))
        if cutoff_ms and ts_ms and ts_ms < cutoff_ms:
            continue

        # レート制限対策
        time.sleep(random.uniform(0.5, 1.0))

        detail_r = _api_get(
            session,
            f"{base}/api/organizations/{org_id}/chat_conversations/{conv['uuid']}",
        )
        if not detail_r.ok:
            logger.warning("[collect_web] 会話詳細取得失敗: %s HTTP %d", conv.get("uuid"), detail_r.status_code)
            continue

        try:
            detail = detail_r.json()
        except Exception as e:
            logger.warning("[collect_web] 会話詳細 JSON パース失敗: %s", e)
            continue

        chat_messages = detail.get("chat_messages", [])
        for msg in chat_messages:
            if msg.get("sender") != "human":
                continue
            text = _extract_text(msg).strip()
            if not text:
                continue
            msg_ms = _iso_to_ms(msg.get("created_at", ""))
            if cutoff_ms and msg_ms and msg_ms < cutoff_ms:
                continue
            messages.append({
                "text": text[:500],
                "timestamp": _ms_to_display(msg_ms),
                "timestamp_ms": msg_ms or 0,
                "project": (conv.get("name") or "")[:30],
            })

    logger.debug("[collect_web] 収集メッセージ数: %d", len(messages))
    return messages


def collect_claude(session_key: str, org_id: str, cutoff_ms: int | None) -> dict:
    """requests で Claude.ai の会話履歴を収集する"""
    result = {"tool": "Claude.ai", "status": "未検出", "messages": [], "period": ""}

    session, _ = _make_client(session_key)
    messages = _fetch_claude_conversations(session, org_id, cutoff_ms)

    if messages is None:
        logger.error("[collect_web] API 認証エラー（401/403）。\n%s", _SESSION_KEY_HELP)
        result["status"] = "未認証"
        return result

    if messages:
        result["status"] = "検出"
        result["messages"] = messages
        timestamps = [m["timestamp"] for m in messages if m["timestamp"] != "unknown"]
        if timestamps:
            result["period"] = f"{min(timestamps)} 〜 {max(timestamps)}"

    return result


def build_output(sources: list[dict], days: int) -> dict:
    """collect_export.py と同一構造の出力 JSON を組み立てる"""
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
        description="ウェブアプリの AI サービスから会話履歴を収集する"
    )
    parser.add_argument(
        "--session-key",
        required=True,
        metavar="VALUE",
        help="Claude.ai の sessionKey クッキー値（Chrome DevTools → Application → Cookies から取得）",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="過去 N 日分に限定（デフォルト: 7、0 = 全期間）",
    )
    parser.add_argument(
        "--service",
        type=str,
        choices=["claude"],
        default="claude",
        help="収集対象サービス（デフォルト: claude）",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="デバッグログを stderr に出力する",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.ERROR,
        format="%(message)s",
        stream=sys.stderr,
    )

    # カットオフ算出
    cutoff_ms = None
    if args.days and args.days > 0:
        cutoff_dt = datetime.now(tz=timezone.utc) - timedelta(days=args.days)
        cutoff_ms = int(cutoff_dt.timestamp() * 1000)

    session_key = args.session_key
    org_id = _fetch_org_id(session_key)

    if not org_id:
        print(
            "[collect_web] org_id が取得できませんでした（sessionKey が無効な可能性）。\n"
            + _SESSION_KEY_HELP,
            file=sys.stderr,
        )
        result = {"tool": "Claude.ai", "status": "未認証", "messages": [], "period": ""}
        output = build_output([result], args.days)
        if sys.platform == "win32":
            sys.stdout.reconfigure(encoding="utf-8")
        json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
        return

    sources = []

    if args.service == "claude":
        sources.append(collect_claude(session_key, org_id, cutoff_ms))

    output = build_output(sources, args.days)

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
