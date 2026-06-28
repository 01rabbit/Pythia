# security-intel-cowork

SOCチーム向け日次セキュリティインテリジェンス自動収集・レポート生成リポジトリ。

## リポジトリ構造

```
.skills/daily-security-intel/SKILL.md   ← メインパイプラインスキル（Claude Code Routines で自動ロード）
pipeline-1-cve.md                        ← Step 1: CVE調査ルール（監視対象23製品リスト含む）
pipeline-1b-apt.md                       ← Step 1b: APT活動調査ルール
pipeline-2-trends.md                     ← Step 2: 動向収集ルール（Section 2: ゼロデイ・トレンド）
pipeline-3-weighting.md                  ← Step 3: 重みづけ・出力ルール
pipeline-report-modes.md                 ← レポートモード定義（モード1〜3）
pipeline-forecast-verification.md        ← 攻撃予報精度検証ルール
pipeline-ai-1.md                         ← Step 1c: AI攻撃調査（Section 1: AI攻撃動向）
pipeline-ai-2.md                         ← Step 3 (AI): AI攻撃重みづけ・出力ルール
pipeline-soc-recommend.md                ← Step 2b: SOC推奨情報収集ルール（Section 4）
pipeline-output-schema.md                ← JSONスキーマ定義・出力ファイル仕様（AI分析・機械処理用）
reported-cves.md                         ← 既報CVEリスト（実行後に自動追記）
reported-apts.md                         ← 既報APT活動リスト（実行後に自動追記）
reported-ai-attacks.md                   ← 既報AI攻撃リスト（実行後に自動追記）
outputs/YYYY-MM-DD/                      ← 日次レポートディレクトリ（実行後に自動生成・コミット）
  YYYY-MM-DD-security-report.json                   ← 構造化JSON・Section 1〜4 全データ（AI分析・機械処理用）★基本形式
  YYYY-MM-DD-security-report.txt                    ← 全セクション完全版 Section 1〜4（Slack共有向け）
  YYYY-MM-DD-security-report-cve.txt                ← Section 3: 製品別CVE（ゼロデイ特報・本編・参考A・参考B）
  YYYY-MM-DD-security-report-zeroday-trends.txt     ← Section 2: ゼロデイ・トレンド（ゼロデイ特報・APT活動・注目CVE・攻撃予報）
  YYYY-MM-DD-security-report-ai.txt                 ← Section 1: AI攻撃動向（本編・参考B・参考A・週次サマリー）
  YYYY-MM-DD-security-report-soc.txt                ← Section 4: SOC推奨情報（高/中/低優先度）
```

## 実行方法

Claude Code Routines が毎日 07:00 JST に `.skills/daily-security-intel/SKILL.md` のパイプラインを自動実行する。
手動実行も可能（Routine 画面から "Run" をクリック）。

## コミットルール

- 実行後は main ブランチへ直接コミット（PRは不要）
- コミットメッセージ: `daily report: YYYY-MM-DD`
- コミット対象ファイル: `reported-cves.md`, `reported-apts.md`, `reported-ai-attacks.md`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.txt`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-cve.txt`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-zeroday-trends.txt`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-ai.txt`,
  `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-soc.txt`

## 出力フォーマット

- 基本形式: `security-report.json`（pipeline-output-schema.md のスキーマ準拠・Section 1〜4 全データ収録）
- 変換形式（5種・JSONから変換・Slack貼り付け前提・Markdown不使用）:
  - `security-report.txt`: 全セクション完全版（Section 1〜4）
  - `security-report-cve.txt`: Section 3 製品別CVE（ゼロデイ特報・本編・参考A・参考B）
  - `security-report-zeroday-trends.txt`: Section 2 ゼロデイ・トレンド（ゼロデイ特報・APT・注目CVE・攻撃予報）
  - `security-report-ai.txt`: Section 1 AI攻撃動向（本編・参考B・参考A・週次サマリー）
  - `security-report-soc.txt`: Section 4 SOC推奨情報（高/中/低優先度）
- デフォルトモード: モード3（CVE・ゼロデイ・APT・AI攻撃 フル版）
- 詳細は `pipeline-3-weighting.md` および `pipeline-output-schema.md` 参照
