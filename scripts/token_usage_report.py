#!/usr/bin/env python3
"""Claude Code セッションのトークン使用量と料金概算（USD / 任意でJPY）を算出する。

Claude Code は各アシスタント応答を JSONL 形式のセッショントランスクリプトへ追記し、
その `message.usage` に API 呼び出しごとの実トークン数を記録している。
本スクリプトはそのトランスクリプトを集計し、モデル別の公開単価を掛けて料金を概算する。

対象トランスクリプト:
  ~/.claude/projects/<cwdをハイフン化したディレクトリ名>/<session-id>.jsonl
  （`CLAUDE_CONFIG_DIR` が設定されている場合はそちらを優先）
  および、そのセッションが Agent ツールでバックグラウンド起動したサブエージェントの分:
  ~/.claude/projects/<同上>/<session-id>/subagents/agent-*.jsonl
  （バックグラウンドサブエージェントの消費はメインセッションファイルへ isSidechain:true
    として記録されるのではなく、この専用ディレクトリへ別ファイルとして記録されるため、
    両方を合算しないと日次パイプラインの Step 1〜3 サブエージェント分が丸ごと欠落する）

使い方:
  # 現在のセッションを集計してテキスト＋JSONを表示
  python3 scripts/token_usage_report.py

  # JSONだけをファイルへ保存（日次レポートの記録用）
  python3 scripts/token_usage_report.py --format json \
      --output outputs/2026-08-02/2026-08-02-token-usage.json

  # 円換算も出す（レートは実勢値を指定。環境変数 USD_JPY_RATE でも可）
  python3 scripts/token_usage_report.py --jpy-rate 150

終了コード: 0=成功 / 1=トランスクリプトが見つからない・集計対象0件
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

JST = timezone(timedelta(hours=9))

# ---------------------------------------------------------------------------
# 単価表（USD / 100万トークン）
#
# 出典: Anthropic 公開価格（platform.claude.com/docs/en/pricing）。
# 値上げ・新モデル追加時はこの表と PRICING_SOURCE_NOTE を更新すること。
# キーはモデルIDの前方一致で照合する（例: claude-haiku-4-5-20251001 → claude-haiku-4-5）。
# ---------------------------------------------------------------------------
PRICES_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    # model id prefix:      (input, output)
    "claude-fable-5": (10.00, 50.00),
    "claude-mythos-5": (10.00, 50.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-opus-4-5": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}

# Fast mode（speed="fast"）適用時の単価。対象は Opus 5 / Opus 4.8 のみ。
FAST_MODE_PRICES_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-5": (10.00, 50.00),
    "claude-opus-4-8": (10.00, 50.00),
}

# Claude Sonnet 5 の導入価格（この日付まで $2/$10、以降は上表の $3/$15）。
SONNET_5_INTRO_PRICES = (2.00, 10.00)
SONNET_5_INTRO_UNTIL = "2026-08-31"

# プロンプトキャッシュの入力単価に対する倍率。
CACHE_WRITE_5M_MULTIPLIER = 1.25
CACHE_WRITE_1H_MULTIPLIER = 2.00
CACHE_READ_MULTIPLIER = 0.10

# サーバーサイドツールの従量課金。Web検索は検索1,000回あたりの単価。
# Web fetch はトークン課金のみで追加課金なし（回数は参考値として出力する）。
WEB_SEARCH_USD_PER_1K = 10.00

PRICING_SOURCE_NOTE = (
    "単価はAnthropic公開価格（入力/出力 USD/1Mトークン、"
    f"キャッシュ書込 5m={CACHE_WRITE_5M_MULTIPLIER}倍・1h={CACHE_WRITE_1H_MULTIPLIER}倍、"
    f"キャッシュ読出 {CACHE_READ_MULTIPLIER}倍、Web検索 ${WEB_SEARCH_USD_PER_1K}/1,000回）に基づく概算。"
    "定額プラン利用時は実請求額とは一致しない。"
)


def transcript_root() -> Path:
    """トランスクリプトの保存ルート（~/.claude/projects 相当）を返す。"""
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    base = Path(config_dir) if config_dir else Path.home() / ".claude"
    return base / "projects"


def project_dir_name(cwd: Path) -> str:
    """カレントディレクトリからトランスクリプト用ディレクトリ名を組み立てる。

    Claude Code は絶対パスの区切り・記号をハイフンへ置換した名前を使う
    （例: /home/user/Pythia → -home-user-Pythia）。
    """
    text = str(cwd.resolve())
    return "".join(char if char.isalnum() else "-" for char in text)


def subagent_transcripts_for(session_file: Path) -> list[Path]:
    """あるセッションファイルに紐づくサブエージェント（Agent ツール・バックグラウンド実行）の
    トランスクリプトを返す。

    Claude Code は Agent ツールで起動したバックグラウンドサブエージェントの応答を、
    メインセッションファイルへ `isSidechain: true` として追記するのではなく、
    `<project_dir>/<session_id>/subagents/agent-*.jsonl` という別ファイル群へ記録する
    （メインセッションファイル自体には isSidechain:true の行は現れない）。
    これを読み漏らすと Step 1〜3 で並列起動した収集・重みづけサブエージェントの消費分が
    トークン量・料金概算から丸ごと欠落するため、必ずここで合算する。
    """
    session_dir = session_file.parent / session_file.stem / "subagents"
    if not session_dir.is_dir():
        return []
    return sorted(session_dir.glob("agent-*.jsonl"), key=lambda p: p.stat().st_mtime)


def discover_transcripts(args: argparse.Namespace) -> list[Path]:
    """集計対象のトランスクリプトファイルを決定する（対応するサブエージェント分も含む）。"""
    if args.transcript:
        paths = [Path(path) for path in args.transcript]
        for path in list(paths):
            paths.extend(subagent_transcripts_for(path))
        return paths

    project_dir = Path(args.project_dir) if args.project_dir else None
    if project_dir is None:
        candidate = transcript_root() / project_dir_name(Path.cwd())
        project_dir = candidate if candidate.is_dir() else None
    if project_dir is None or not project_dir.is_dir():
        return []

    files = sorted(project_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not files:
        return []
    if args.all_sessions:
        result = list(files)
        for path in files:
            result.extend(subagent_transcripts_for(path))
        return result

    session_id = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if session_id:
        current = project_dir / f"{session_id}.jsonl"
        if current.is_file():
            return [current, *subagent_transcripts_for(current)]
    # セッションIDが取れない場合は最終更新のファイル（＝実行中のセッション）を使う。
    current = files[-1]
    return [current, *subagent_transcripts_for(current)]


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def resolve_rates(model: str, usage: dict, measured_date: str) -> tuple[str | None, tuple[float, float] | None]:
    """モデルIDから (照合したキー, (入力単価, 出力単価)) を返す。未知モデルは (None, None)。"""
    matches = [key for key in PRICES_USD_PER_MTOK if model.startswith(key)]
    if not matches:
        return None, None
    key = max(matches, key=len)  # 最長一致（claude-opus-4-8 と claude-opus-4 の混同を避ける）

    if usage.get("speed") == "fast" and key in FAST_MODE_PRICES_USD_PER_MTOK:
        return key, FAST_MODE_PRICES_USD_PER_MTOK[key]
    if key == "claude-sonnet-5" and measured_date <= SONNET_5_INTRO_UNTIL:
        return key, SONNET_5_INTRO_PRICES
    return key, PRICES_USD_PER_MTOK[key]


def empty_bucket() -> dict:
    return {
        "api_requests": 0,
        "tokens": {
            "input": 0,
            "cache_write_5m": 0,
            "cache_write_1h": 0,
            "cache_read": 0,
            "output": 0,
            "total": 0,
        },
        "cost_usd": {
            "input": 0.0,
            "cache_write": 0.0,
            "cache_read": 0.0,
            "output": 0.0,
            "total": 0.0,
        },
        "priced": True,
    }


def collect(paths: list[Path], since: datetime | None, measured_date: str) -> dict:
    """トランスクリプトを走査し、モデル別・全体のトークン量と料金を集計する。"""
    by_model: dict[str, dict] = {}
    seen_requests: set[str] = set()
    session_ids: list[str] = []
    web_search_requests = 0
    web_fetch_requests = 0
    unknown_models: set[str] = set()
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for path in paths:
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # 書き込み途中の行は読み飛ばす
                if not isinstance(record, dict) or record.get("type") != "assistant":
                    continue

                message = record.get("message")
                if not isinstance(message, dict):
                    continue
                usage = message.get("usage")
                if not isinstance(usage, dict):
                    continue

                timestamp = parse_timestamp(record.get("timestamp"))
                if since is not None and timestamp is not None and timestamp < since:
                    continue

                # 同一API応答が複数行に分割記録されるため requestId / message.id で重複排除する。
                dedupe_key = record.get("requestId") or message.get("id") or record.get("uuid")
                if not dedupe_key or dedupe_key in seen_requests:
                    continue
                seen_requests.add(str(dedupe_key))

                model = str(message.get("model") or "unknown")
                if model.startswith("<"):
                    continue  # <synthetic> 等の内部生成メッセージは課金対象外

                session_id = record.get("sessionId")
                if isinstance(session_id, str) and session_id not in session_ids:
                    session_ids.append(session_id)
                if timestamp is not None:
                    first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
                    last_ts = timestamp if last_ts is None else max(last_ts, timestamp)

                cache_creation = usage.get("cache_creation")
                if isinstance(cache_creation, dict):
                    write_5m = int(cache_creation.get("ephemeral_5m_input_tokens") or 0)
                    write_1h = int(cache_creation.get("ephemeral_1h_input_tokens") or 0)
                else:
                    # 内訳が無い旧形式は 5分TTL として扱う（倍率の低い側＝過小見積りを避けるため
                    # ではなく、既定TTLが5分であるという実態に合わせる）。
                    write_5m = int(usage.get("cache_creation_input_tokens") or 0)
                    write_1h = 0

                tokens_in = int(usage.get("input_tokens") or 0)
                cache_read = int(usage.get("cache_read_input_tokens") or 0)
                tokens_out = int(usage.get("output_tokens") or 0)

                server_tool_use = usage.get("server_tool_use")
                if isinstance(server_tool_use, dict):
                    web_search_requests += int(server_tool_use.get("web_search_requests") or 0)
                    web_fetch_requests += int(server_tool_use.get("web_fetch_requests") or 0)

                bucket = by_model.setdefault(model, empty_bucket())
                bucket["api_requests"] += 1
                bucket["tokens"]["input"] += tokens_in
                bucket["tokens"]["cache_write_5m"] += write_5m
                bucket["tokens"]["cache_write_1h"] += write_1h
                bucket["tokens"]["cache_read"] += cache_read
                bucket["tokens"]["output"] += tokens_out

                matched_key, rates = resolve_rates(model, usage, measured_date)
                if rates is None:
                    unknown_models.add(model)
                    bucket["priced"] = False
                    continue
                bucket["price_key"] = matched_key
                price_in, price_out = rates
                bucket["cost_usd"]["input"] += tokens_in * price_in / 1_000_000
                bucket["cost_usd"]["cache_write"] += (
                    write_5m * price_in * CACHE_WRITE_5M_MULTIPLIER
                    + write_1h * price_in * CACHE_WRITE_1H_MULTIPLIER
                ) / 1_000_000
                bucket["cost_usd"]["cache_read"] += (
                    cache_read * price_in * CACHE_READ_MULTIPLIER / 1_000_000
                )
                bucket["cost_usd"]["output"] += tokens_out * price_out / 1_000_000

    totals = empty_bucket()
    for bucket in by_model.values():
        bucket["tokens"]["total"] = sum(bucket["tokens"][key] for key in
                                        ("input", "cache_write_5m", "cache_write_1h", "cache_read", "output"))
        bucket["cost_usd"]["total"] = sum(bucket["cost_usd"][key] for key in
                                          ("input", "cache_write", "cache_read", "output"))
        totals["api_requests"] += bucket["api_requests"]
        for key in bucket["tokens"]:
            totals["tokens"][key] += bucket["tokens"][key]
        for key in bucket["cost_usd"]:
            totals["cost_usd"][key] += bucket["cost_usd"][key]
        totals["priced"] = totals["priced"] and bucket["priced"]

    server_tools_cost = web_search_requests * WEB_SEARCH_USD_PER_1K / 1000

    return {
        "by_model": by_model,
        "totals": totals,
        "server_tools": {
            "web_search_requests": web_search_requests,
            "web_fetch_requests": web_fetch_requests,
            "cost_usd": server_tools_cost,
        },
        "session_ids": session_ids,
        "unknown_models": sorted(unknown_models),
        "first_message_at": first_ts.astimezone(JST).isoformat() if first_ts else None,
        "last_message_at": last_ts.astimezone(JST).isoformat() if last_ts else None,
    }


def build_result(collected: dict, paths: list[Path], measured_at: datetime,
                 jpy_rate: float | None, label: str | None) -> dict:
    totals = collected["totals"]
    grand_total_usd = totals["cost_usd"]["total"] + collected["server_tools"]["cost_usd"]

    notes = [PRICING_SOURCE_NOTE]
    if collected["unknown_models"]:
        notes.append(
            "単価未登録のモデルが含まれるため料金は過小評価: "
            + ", ".join(collected["unknown_models"])
        )
    notes.append("計測はこのスクリプト実行時点のスナップショット。以降の処理分は含まない。")

    result = {
        "measured_at": measured_at.astimezone(JST).isoformat(),
        "label": label,
        "session_ids": collected["session_ids"],
        "transcripts": [str(path) for path in paths],
        "first_message_at": collected["first_message_at"],
        "last_message_at": collected["last_message_at"],
        "api_requests": totals["api_requests"],
        "tokens": totals["tokens"],
        "server_tools": collected["server_tools"],
        "cost_usd": {
            **totals["cost_usd"],
            "server_tools": collected["server_tools"]["cost_usd"],
            "grand_total": round(grand_total_usd, 6),
        },
        "cost_jpy": round(grand_total_usd * jpy_rate, 1) if jpy_rate else None,
        "jpy_rate": jpy_rate,
        "cost_is_complete": totals["priced"],
        "by_model": collected["by_model"],
        "notes": notes,
    }
    for bucket in result["by_model"].values():
        for key, value in bucket["cost_usd"].items():
            bucket["cost_usd"][key] = round(value, 6)
    for key, value in result["cost_usd"].items():
        result["cost_usd"][key] = round(value, 6)
    return result


def render_text(result: dict) -> str:
    tokens = result["tokens"]
    cost = result["cost_usd"]
    lines: list[str] = []
    header = f"=== トークン使用量・料金概算（計測時点: {result['measured_at']}） ==="
    lines.append(header)
    if result["label"]:
        lines.append(f"対象: {result['label']}")
    lines.append(f"API呼び出し回数: {result['api_requests']:,} 回"
                 f"（サブエージェント分を含む）")
    lines.append("")
    lines.append("【トークン量】")
    lines.append(f"  入力（キャッシュ外）  : {tokens['input']:>12,} tok")
    lines.append(f"  キャッシュ書き込み(5m): {tokens['cache_write_5m']:>12,} tok")
    lines.append(f"  キャッシュ書き込み(1h): {tokens['cache_write_1h']:>12,} tok")
    lines.append(f"  キャッシュ読み出し    : {tokens['cache_read']:>12,} tok")
    lines.append(f"  出力                  : {tokens['output']:>12,} tok")
    lines.append(f"  合計                  : {tokens['total']:>12,} tok")
    lines.append("")
    lines.append("【料金概算（USD）】")
    lines.append(f"  入力                  : ${cost['input']:>10,.4f}")
    lines.append(f"  キャッシュ書き込み    : ${cost['cache_write']:>10,.4f}")
    lines.append(f"  キャッシュ読み出し    : ${cost['cache_read']:>10,.4f}")
    lines.append(f"  出力                  : ${cost['output']:>10,.4f}")
    web_search = result["server_tools"]["web_search_requests"]
    lines.append(f"  Web検索             : ${cost['server_tools']:>10,.4f}（{web_search:,} 回）")
    lines.append(f"  合計                  : ${cost['grand_total']:>10,.4f}"
                 + (f"（約 {result['cost_jpy']:,.0f} 円 @{result['jpy_rate']}円/USD）"
                    if result["cost_jpy"] is not None else ""))
    if not result["cost_is_complete"]:
        lines.append("  ※ 単価未登録モデルを含むため過小評価")
    lines.append("")
    lines.append("【モデル別】")
    for model, bucket in sorted(result["by_model"].items()):
        lines.append(f"  {model}: {bucket['tokens']['total']:,} tok / "
                     f"${bucket['cost_usd']['total']:,.4f} / {bucket['api_requests']:,} 回")
    lines.append("")
    lines.append(f"Web fetch 回数（追加課金なし・参考）: {result['server_tools']['web_fetch_requests']:,} 回")
    for note in result["notes"]:
        lines.append(f"注: {note}")
    return "\n".join(lines)


def render_markdown(result: dict) -> str:
    """PR本文・PRコメントへ貼り付けるMarkdown表を返す。"""
    tokens = result["tokens"]
    cost = result["cost_usd"]
    jpy = (f" / 約 {result['cost_jpy']:,.0f} 円（@{result['jpy_rate']}円）"
           if result["cost_jpy"] is not None else "")
    lines = [
        "### トークン使用量・料金概算",
        "",
        f"| 区分 | トークン量 | 料金概算 (USD) |",
        f"|---|---:|---:|",
        f"| 入力（キャッシュ外） | {tokens['input']:,} | ${cost['input']:,.4f} |",
        f"| キャッシュ書き込み | {tokens['cache_write_5m'] + tokens['cache_write_1h']:,} | ${cost['cache_write']:,.4f} |",
        f"| キャッシュ読み出し | {tokens['cache_read']:,} | ${cost['cache_read']:,.4f} |",
        f"| 出力 | {tokens['output']:,} | ${cost['output']:,.4f} |",
        f"| Web検索 {result['server_tools']['web_search_requests']:,}回 | - | ${cost['server_tools']:,.4f} |",
        f"| **合計** | **{tokens['total']:,}** | **${cost['grand_total']:,.4f}**{jpy} |",
        "",
        f"API呼び出し {result['api_requests']:,} 回"
        f"（モデル: {', '.join(sorted(result['by_model'])) or '-'}）／"
        f"計測時点: {result['measured_at']}",
        "",
        f"<sub>{PRICING_SOURCE_NOTE}</sub>",
    ]
    if not result["cost_is_complete"]:
        lines.append("")
        lines.append("> ⚠️ 単価未登録のモデルが含まれるため、料金は過小評価です。")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transcript", action="append",
                        help="集計対象のトランスクリプト（.jsonl）。複数指定可。省略時は自動検出")
    parser.add_argument("--project-dir", help="トランスクリプト格納ディレクトリを明示指定する")
    parser.add_argument("--all-sessions", action="store_true",
                        help="プロジェクト配下の全セッションを合算する（既定は現在のセッションのみ）")
    parser.add_argument("--since", help="この時刻以降のメッセージのみ集計（ISO 8601）")
    parser.add_argument("--since-minutes", type=int,
                        help="直近N分のメッセージのみ集計")
    parser.add_argument("--label", help="出力に添える対象名（例: daily report 2026-08-02）")
    parser.add_argument("--jpy-rate", type=float,
                        default=float(os.environ["USD_JPY_RATE"]) if os.environ.get("USD_JPY_RATE") else None,
                        help="USD→JPY換算レート。環境変数 USD_JPY_RATE でも指定可（省略時は円換算なし）")
    parser.add_argument("--format", choices=["text", "json", "markdown", "both"], default="both",
                        help="標準出力の形式（既定: both = テキスト＋JSON）")
    parser.add_argument("--output", help="JSONを書き出すファイルパス")
    parser.add_argument("--from-json",
                        help="既に計測済みのJSONを読み込んで再描画する（再計測しないため数値が完全に一致する。"
                             "PR本文用のMarkdown表を後から作る場合に使う）")
    args = parser.parse_args(argv)

    if args.from_json:
        source = Path(args.from_json)
        if not source.is_file():
            print(f"指定されたJSONが存在しません: {source}", file=sys.stderr)
            return 1
        result = json.loads(source.read_text(encoding="utf-8"))
        return emit(result, args)

    paths = discover_transcripts(args)
    for path in paths:
        if not path.is_file():
            print(f"警告: トランスクリプトが存在しません: {path}", file=sys.stderr)
    if not paths:
        print("トランスクリプトが見つかりません。--transcript でパスを指定してください。",
              file=sys.stderr)
        return 1

    since = parse_timestamp(args.since) if args.since else None
    if since is None and args.since_minutes:
        since = datetime.now(timezone.utc) - timedelta(minutes=args.since_minutes)

    measured_at = datetime.now(timezone.utc)
    collected = collect(paths, since, measured_at.astimezone(JST).date().isoformat())
    if collected["totals"]["api_requests"] == 0:
        print("集計対象のAPI呼び出しが0件でした（対象期間・トランスクリプトを確認してください）。",
              file=sys.stderr)
        return 1

    result = build_result(collected, paths, measured_at, args.jpy_rate, args.label)
    return emit(result, args)


def emit(result: dict, args: argparse.Namespace) -> int:
    """集計結果をファイル・標準出力へ書き出す。"""
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")

    if args.format in ("text", "both"):
        print(render_text(result))
    if args.format == "markdown":
        print(render_markdown(result))
    if args.format in ("json", "both"):
        if args.format == "both":
            print()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
