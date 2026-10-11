---
name: collect-evidence
description: RSSフィード収集とEvidence Ledger固定タスク（毎日03:17 JSTに実行・GitHub Actions `daily-pipeline.yml` の代替）
---

# collect-evidence — 日次フィード収集・証跡固定（GitHub Actions代替）

## 背景

本タスクは `.github/workflows/daily-pipeline.yml`（Daily Feed Collection）が
GitHub Actions の実行時間上限に達し動かせない間の代替である。
**現在の状態（2026-10-11）: Actions は稼働中のため本スキルの Routine「情報収集（臨時）」は
無効化済み。** 2026-10-06〜07 に Actions と本 Routine が同時に動き二重収集（PR #263）が
発生したため、収集は Actions に統一した。Actions が再び止まった場合のみ Routines 画面から
再有効化し、回復後は再度無効化する。
同ワークフローと**同一の処理・同一のコミットメッセージ規約**を、
GitHub Actionsではなく Claude Code Routines（本スキル）で実行する。

★このスキルの実行時刻（03:17 JST）は、日次パイプライン本体
（ルート `SKILL.md`・07:00 JST 実行）より前でなければならない。
`pipeline-forecast-verification.md` の M5 時刻順序ゲートは「証拠が予報固定時刻より
前に取得されている」ことを前提にしており、本スキルが遅延・失敗すると
Evidence Ledger が当日分空のまま日次パイプラインが実行される
（fail-closed で予報・戦術予報が安全側に倒れるだけで日次レポート自体は生成される。
2026-09-24 に実際に発生した事象を参照）。

GitHub Actions の時間上限が回復し `daily-pipeline.yml` の `schedule:` トリガーを
再開する場合は、本スキルの Routines 登録を外すか、どちらか一方だけが動くようにする
（同時刻に二重実行すると `security-intel-collector/data/` と
`forecaster/evidence/` で競合コミットが発生しうる）。

## 実行手順

以下を `.github/workflows/daily-pipeline.yml` の `collect-feeds` ジョブ（**締めの回**）と
完全に同一の順序・同一のコマンドで実行する（手順を変更・省略しない）。
同ワークフローは 2026-10-11 以降 2 時間おきの多頻度取得も行うが、本スキルが代替するのは
03:17 JST の締めの回だけである（多頻度分を Routine で代替すると Routine の実行回数と
トークンが増えるため行わない。その間の取りこぼしは受け入れる）。

### Step 1: RSS フィード収集

```bash
cd /home/user/Pythia/security-intel-collector
python3 watcher.py
cd /home/user/Pythia
```

### Step 2: 証跡・チャネル被覆の固定

★この時点の取得が「予報固定時刻より前の証跡」になる。取得しそこねても
日次パイプライン側で取り直さない（取り直すと先見性の主張が崩れるため）。

```bash
TODAY=$(TZ=Asia/Tokyo date +%F)
python3 scripts/snapshot_sources.py --date "${TODAY}"
python3 scripts/collect_channel_evidence.py --date "${TODAY}" || true
python3 scripts/record_source_coverage.py --rule tf1-exploitation-v3 --from-evidence "${TODAY}"
python3 scripts/record_source_coverage.py --rule tf1-poc-v3 --from-evidence "${TODAY}"
python3 scripts/snapshot_sources.py --date "${TODAY}" --verify-only
```

- 個々のフィード取得失敗は日次を止めない（該当チャネルの被覆が不成立になり、
  未確認は miss ではなく not_observed のまま残る。fail-closed）。
- `snapshot_sources.py --verify-only` がエラーを返した場合も処理は継続してよいが、
  エラー内容をこの後のコミットメッセージ・チャット報告に必ず記録する
  （黙って握りつぶさない）。

### Step 3: 変更のコミット・push

```bash
git add security-intel-collector/data/ forecaster/evidence/
git diff --cached --quiet && echo "No new feeds collected." && exit 0
DATE=$(TZ=Asia/Tokyo date +%Y-%m-%d)
git commit -m "collect: rss feeds + evidence ${DATE}"
```

コミットメッセージは `daily-pipeline.yml` と同一形式（`collect: rss feeds + evidence YYYY-MM-DD`）
を厳守する。日次パイプライン側（ルート `SKILL.md`）がこの文言でコミット履歴を
判別する箇所はないが、Git 履歴上の一貫性のために形式を合わせる。

**push方式**: `git push -u origin <現在のブランチ>` を試みる。

- main へ直接pushできる環境（このリポジトリの既定の運用）ではそのままpushする。
  `daily-pipeline.yml` も main へ直接pushしている。
- セッションの実行環境がブランチ+PR運用を強制する場合（main への直接pushが拒否される場合）:
  1. push先ブランチから main への PR を作成する（draft で作成してよい）
  2. 作成直後に PR を ready for review へ変更する（draft 解除）
  3. PR を即座に main へマージする（auto-merge が有効なら有効化、無効なら直接マージ）。
     いずれも失敗する場合のみ、人間のマージ判断を待つ旨をチャットに記録する。
  （ルート `SKILL.md` Step 4 の日次レポートPR運用と同一の扱い。
  2026-08-18 user-decision (01rabbit): 収集専用PRも同様に自動マージしてよい）

### Step 4: 完了報告

チャットの最終メッセージで以下を簡潔に報告する（日本語）:

- 実行日時（JST）
- 収集結果: 新規フィード件数（`security-intel-collector/data/raw/` の `new_items`）
- Evidence Ledger: 固定した evidence 件数、`--verify-only` の結果（OK / エラー内容）
- チャネル被覆: `record_source_coverage.py` の結果概要
- コミット/push先（ブランチ名）・PRを作成した場合はその番号
- 変更なしで終了した場合はその旨のみ簡潔に報告する

## 重要ルール

- 変更してよいのは `security-intel-collector/data/` と `forecaster/evidence/` のみ。
  日次レポート本体（`outputs/`）・`forecaster/observations/` 等・`forecaster/knowledge/`
  には一切触れない（`forecaster/knowledge/` の自動書き換え禁止は CLAUDE.md 行動原則5）。
- 本スキルは収集・証跡固定のみを行う。CVE/APT/AI攻撃の調査・分析・レポート生成は
  行わない（それはルート `SKILL.md`・07:00 JST 実行の役割）。
- 取得に使う情報源・スクリプトは `daily-pipeline.yml` と完全に同一のものを使う。
  代替手段（別のフィードURL・別のツール）への差し替えは行わない。
