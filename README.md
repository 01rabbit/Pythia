# 日次セキュリティインテリジェンス自動収集パイプライン

SOCチーム向け。Claude Code Routines によりクラウド上で毎日自動実行される。
CVE・APT活動・AI攻撃動向・SOC推奨情報を収集・重みづけし、プレーンテキストレポートと構造化JSONを生成する。

---

## 自動実行の仕組み

### Claude Code Routines（現行）

```
Claude Code Routines（クラウド）
  └─ 毎日 07:00 JST に自動起動
       └─ SKILL.md を読み込みパイプライン実行（Step 0〜4 + forecaster Step 3.5）
            └─ 結果を outputs/YYYY-MM-DD/ + forecaster/ に保存 → main へ直接コミット
```

手動実行する場合は Routines 画面の「Run」をクリックする。

### GitHub Actions（並行運用・移行先）

```
.github/workflows/daily-pipeline.yml
  └─ 毎日 07:00 JST (22:00 UTC) にトリガー
       ├─ RSS フィード収集 (security-intel-collector/watcher.py)
       └─ Claude Code CLI でパイプライン実行（SKILL.md 準拠）

.github/workflows/weekly-verify.yml
  └─ 火曜・木曜 12:00 JST (03:00 UTC) にトリガー
       └─ 予報精度検証（forecaster/prompts/04-verify.md）
```

#### GitHub Actions の役割分担

GitHub ActionsはLLMを使わない純粋な自動化のみを担当する。
LLM処理（分析・予報・コミット）はすべてClaude Code Routinesが行う。

| ワークフロー | タイミング | 役割 |
|---|---|---|
| `daily-pipeline.yml` | 06:00 JST（Routines実行1時間前） | RSSフィード収集のみ（Python） |
| `weekly-verify.yml` | 火・木 11:55 JST | 検証タスクのIssue作成（リマインド） |

外部APIキー不要。`GITHUB_TOKEN`（自動付与）のみで動作する。

---

## ファイル構成

```
.skills/
  daily-security-intel/SKILL.md     ← 日次パイプラインのエントリポイント（Routineが自動ロード）
  forecast-verification/SKILL.md    ← 攻撃予報の精度検証（毎週火曜・木曜 12:00 JST に自動実行）

pipeline-1-cve.md                   ← Step 1:  CVE調査ルール（監視対象製品リスト含む）
pipeline-1b-apt.md                  ← Step 1b: APT活動調査ルール
pipeline-ai-1.md                    ← Step 1c: AI攻撃調査ルール
pipeline-2-trends.md                ← Step 2:  動向収集ルール
pipeline-3-weighting.md             ← Step 3:  CVE/APT 重みづけ・出力テンプレート
pipeline-ai-2.md                    ← Step 3:  AI攻撃 重みづけ・出力テンプレート
pipeline-soc-recommend.md           ← Step 3:  SOC推奨情報 収集・出力ルール
pipeline-report-modes.md            ← 出力ファイル定義・ゼロデイ特報テンプレート
pipeline-output-schema.md           ← 構造化JSON（security-report.json）スキーマ定義
pipeline-forecast-verification.md   ← 攻撃予報 精度検証ルール・フォーマット

reported-cves.md                    ← 既報CVEリスト（重複除外用・実行後に自動追記）
reported-apts.md                    ← 既報APT活動リスト（重複除外用・実行後に自動追記）
reported-ai-attacks.md              ← 既報AI攻撃リスト（重複除外用・実行後に自動追記）

outputs/YYYY-MM-DD/                 ← 日次レポート（実行後に自動生成）
  YYYY-MM-DD-security-report.json                  ← 全セクション構造化JSON（AI分析・機械処理用）
  YYYY-MM-DD-security-report.txt                   ← 全セクション完全版
  YYYY-MM-DD-security-report-cve.txt               ← Section 3: 製品別CVE
  YYYY-MM-DD-security-report-zeroday-trends.txt    ← Section 2: ゼロデイ・トレンド
  YYYY-MM-DD-security-report-ai.txt                ← Section 1: AI攻撃動向
  YYYY-MM-DD-security-report-soc.txt               ← Section 4: SOC推奨情報

verification/YYYY-MM-DD-verification.md  ← 攻撃予報 精度検証結果（PRで管理）
```

---

## パイプラインの流れ

```
Step 0  時刻確認・調査期間確定
         └─ 対象期間: 前日 07:00 JST 〜 当日 07:00 JST

Step 1  情報収集（3トラック並行）
         ├─ Step 1:  CVE調査    — NVD / CISA KEV / GitHub Advisory / ベンダー
         ├─ Step 1b: APT活動    — Mandiant / MSTIC / CrowdStrike / Unit 42 / CISA合同勧告
         └─ Step 1c: AI攻撃     — MITRE ATLAS / OWASP GenAI / arXiv / AI Incident DB

Step 2  動向収集
         ├─ 英語ソース: BleepingComputer / The Hacker News / SecurityWeek 等
         └─ 日本語ソース（必須）: Security NEXT / JPCERT/CC / IPA / ScanNetSecurity 等

Step 3  重みづけ・スコアリング・出力
         ├─ CVE:    技術深刻度 × 実環境影響
         ├─ APT:    信頼性・活動深刻度 × キャンペーン規模・影響範囲
         ├─ AI攻撃: 実証・悪用深刻度 × 影響範囲・実害
         ├─ security-report.json を生成（JSON-first）
         └─ JSON から 5種のテキストファイルに変換

Step 4  ファイル更新・コミット
         ├─ reported-cves.md / reported-apts.md / reported-ai-attacks.md に追記
         └─ outputs/YYYY-MM-DD/ を保存 → main へ直接コミット
              コミットメッセージ: "daily report: YYYY-MM-DD"
```

---

## 出力レポートの構成

| ファイル | 内容 | 主な用途 |
|---|---|---|
| security-report.json | Section 1〜4 全データ（構造化） | AI分析・機械処理 |
| security-report.txt | Section 1〜4 完全版 | 日次レビュー・共有 |
| security-report-cve.txt | Section 3: ゼロデイ特報・本編CVE・参考A・参考B | CVE担当 |
| security-report-zeroday-trends.txt | Section 2: ゼロデイ特報・APT活動・攻撃予報 | トレンド担当 |
| security-report-ai.txt | Section 1: AI攻撃動向・週次サマリー | AI担当 |
| security-report-soc.txt | Section 4: SOC推奨情報（高/中/低優先度） | SOC担当 |

テキストファイルはすべてプレーンテキスト（Markdown記法なし）。

---

## 攻撃予報 精度検証（別Routine）

毎週火曜・木曜 12:00 JST に `.skills/forecast-verification/SKILL.md` が自動実行される。
過去 7 日分のレポートから攻撃予報を抽出し、的中率を検証した結果を
`verification/YYYY-MM-DD-verification.md` に保存してPRを発行する。

---

## コミットルール

| ケース | ブランチ | PR |
|---|---|---|
| 日次レポート | main へ直接コミット | 不要 |
| 攻撃予報 精度検証 | `verify/YYYY-MM-DD` | main へPR発行 |

---

## ファイルを編集したい場合

| 目的 | 編集ファイル |
|---|---|
| 監視対象製品の追加・変更 | `pipeline-1-cve.md` |
| APT追跡対象の変更 | `pipeline-1b-apt.md` |
| 重みづけ基準の調整 | `pipeline-3-weighting.md` |
| 出力テンプレートの変更 | `pipeline-3-weighting.md` / `pipeline-ai-2.md` / `pipeline-soc-recommend.md` |
| JSONスキーマの変更 | `pipeline-output-schema.md` |
| パイプライン実行手順の変更 | `SKILL.md` |
| PYTHIAのスコープ・フェーズ設定 | `config.yml` |
| 正規化ルール | `forecaster/prompts/01-normalize.md` |
| 予報ロジック | `forecaster/prompts/03-forecast.md` |
| 検証ルール | `forecaster/prompts/04-verify.md` |

---

## PYTHIA 戦術予報士サブシステム

```
forecaster/
  phase1-config.json          ← Phase 1 設定（フォーカスグループ: Lazarus Group）
  schema/observation.schema.json  ← ATT&CK 正規化スキーマ
  knowledge/                  ← 空で起動。検証ループで育てる
  observations/YYYY/MM/       ← 日次正規化済み観測データ
  baseline/                   ← TTP出現頻度・グループ活性度の平常統計
  forecasts/daily/            ← 日次サイバー脅威予報
  verification/               ← 予報 × 実績の突合記録（月次JSON）
  prompts/                    ← 4ステージパイプラインのプロンプト
```

予報精度は「予報 → 実績突合 → knowledge補正 → 再予報」の検証ループで改善する。
`knowledge/` への自動書き換えは禁止。人間レビューを経てマージする（GitHub Issue経由）。
