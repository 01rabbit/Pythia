---
name: daily-security-intel
description: 毎日定時に実行するセキュリティインテリジェンス収集・重みづけ・レポート生成タスク
schedule: daily
---

# 日次セキュリティインテリジェンス パイプライン

## 実行前に必ず読むファイル
1. `reported-cves.md` — 既報CVEリスト（重複除外に使用）
2. `reported-apts.md` — 既報APT活動リスト（重複除外に使用）
3. `pipeline-1-cve.md` — Step 1 CVE調査ルール（監視対象23製品リスト含む）
4. `pipeline-1b-apt.md` — Step 1b APT活動調査ルール
5. `pipeline-2-trends.md` — Step 2 動向収集ルール
6. `pipeline-3-weighting.md` — Step 3 重みづけ・出力ルール
7. `pipeline-soc-recommend.md` — Step 2b SOC推奨情報収集ルール

## レポート区分（3区分）

本パイプラインは以下の3区分でレポートを構成する:

```
Section 1: AI攻撃動向
  → pipeline-ai-1.md で収集・分類（カテゴリA/B/C）
  → pipeline-ai-2.md で重みづけ・出力

Section 2: ゼロデイ・セキュリティトレンド
  → ゼロデイ特報（CISA KEV・実悪用確認・ゼロデイ報道）
  → APT活動（pipeline-1b-apt.md / pipeline-2-trends.md）
  → 攻撃トレンド（BleepingComputer / THN / SecurityWeek 等）
  → 注目CVE（リスト外製品 — トラック B CVE: CVSS9.0以上・KEV・ゼロデイ等）

Section 3: 製品別CVE
  → pipeline-1-cve.md の「監視対象製品リスト」（23製品）を対象
  → 製品ごとにCVEを収集・優先度評価
  → 本編 / 参考A（国内）/ 参考B（国際先行）/ 除外サマリー

Section 4: GMOイエラエSOC推奨情報
  → pipeline-soc-recommend.md で収集・分類
  → 監視対象23製品以外で CVE・ゼロデイ・AI攻撃の3観点に関連して注目すべき情報
  → 優先度タグ（高 / 中 / 低）で分類
```

---

## 実行手順

### Step 0: 時刻確認・期間確定
- 現在時刻（JST）を取得する
- 調査対象期間 = 現在時刻 − 24時間

### Step 1: CVE調査（pipeline-1-cve.md に従う）
- **トラック A（製品別CVE / Section 3 向け）**:
  監視対象製品リスト（23製品）のCVEを NVD / CISA KEV / ベンダーアドバイザリで横断検索
  期間内に A〜H の変化が確認できるCVEを収集。`reported-cves.md` と照合し既報除外
- **トラック B（トレンドCVE / Section 2 向け）**:
  リスト外製品で CVSS 9.0以上・CISA KEV・ゼロデイ・実悪用・PoC公開等の高インパクトCVEを収集
  `section_route: trends` タグを付けて Step 2 へ渡す
- 除外基準はフラグ付け（足切りしない）

### Step 1b: APT活動調査（pipeline-1b-apt.md に従う）※Step 1 と並行実行
- Mandiant / MSTIC / CrowdStrike / Unit 42 / CISA合同勧告等を横断検索
- 期間内に P〜W の変化が確認できる活動のみ収集（→ Section 2 へ）
- `reported-apts.md` と照合し、既報かつ変化なしは除外
- 除外基準はフラグ付け（足切りしない）

### Step 1c: AI攻撃調査（pipeline-ai-1.md に従う）※Step 1 / 1b と並行実行
- AI攻撃カテゴリ A（AI武器化）/ B（AI攻撃対象）/ C（AIインフラ）を横断調査（→ Section 1 へ）
- `reported-ai-attacks.md` と照合し既報除外
- Temporal Burst Filtering を適用（3件未満 → 低優先度）

### Step 2: 動向収集（pipeline-2-trends.md に従う）
- 英語ソース: BleepingComputer / The Hacker News / SecurityWeek / Mandiant 等
- 日本語ソース（必須）: Security NEXT / JPCERT/CC 注意喚起 / IPA重要情報 / ScanNetSecurity
- APT補完ソース: MSTIC / CrowdStrike / Unit 42 / NISC / 警察庁サイバー警察局
- Step 1 トラック B から渡された `section_route: trends` CVEを受け取り Section 2 へ統合
- 24時間窓内の記事・更新のみ対象、件数制限なし

### Step 2b: SOC推奨情報収集（pipeline-soc-recommend.md に従う）※Step 2 と並行実行
- 各Stepの調査中にストックした「Section 1〜3 に収まらないが注目すべき情報」を精査
- 採用条件 α〜η を適用し、期間内の変化が確認できるもののみ採用
- JPCERT/CC / IPA / 警察庁 / SANS ISC / Krebs 等を補完確認
- 優先度タグ（高 / 中 / 低）を付与して Step 3 へ渡す

### Step 3: 重みづけ・出力（pipeline-3-weighting.md に従う）
- Section 3 CVE: 軸1（技術深刻度）× 軸2（実環境影響）で評価、製品単位で集計
- Section 2 CVE（トラック B）: 同上の重みづけを適用しゼロデイ特報・本編・参考A/B へ振り分け
- APT: 軸P（信頼性・活動深刻度）× 軸Q（キャンペーン規模・影響範囲）で評価
- Section 1 AI攻撃: pipeline-ai-2.md の軸X × 軸Y で評価
- 日本語ソースが確認できたCVEは参考A昇格トリガーを自動適用
- 出力セクション構成:
    [Section 1] AI攻撃動向-本編 / 参考B / 参考A / 週次サマリー / 除外
    [Section 2] ゼロデイ特報 / APT活動-本編 / APT活動-注目動向 / 注目CVE（リスト外） / 攻撃予報 / 除外
    [Section 3] 製品別CVE-本編 / 参考A（国内）/ 参考B（国際先行）/ 除外サマリー
    [Section 4] GMOイエラエSOC推奨情報（高優先度 → 中 → 低）

### Step 3.5: 予報士システム — 正規化・ベースライン更新・予報生成（forecaster 統合）

> この Step は forecaster/ サブシステムへの統合ポイントである。
> Step 3 の出力 JSON が確定してから実行する。既存 collect ロジックには一切手を加えない。

1. **正規化（01-normalize.md）**:
   `forecaster/prompts/01-normalize.md` を読み、当日レポート JSON から observation データを生成する。
   出力先: `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`

2. **ベースライン更新（02-baseline.md）**:
   `forecaster/prompts/02-baseline.md` を読み、observations 全履歴からベースライン統計を更新する。
   ベースライン期間が14日未満の場合はその旨をチャットに報告するが、処理は継続する。

3. **予報生成（03-forecast.md）**:
   `forecaster/prompts/03-forecast.md` を読み、定量的根拠に基づいた予報を生成する。
   出力先: `forecaster/forecasts/daily/YYYY-MM-DD.md`
   ※ベースライン期間が14日未満の場合は定量スコアを根拠として使用せず、
     `pipeline-forecast-verification.md` のルールのみで予報を作成する。

コミット対象に以下を追加する（Step 4 と合わせてコミット）:
- `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`
- `forecaster/baseline/technique-freq.json`
- `forecaster/baseline/group-activity.json`
- `forecaster/forecasts/daily/YYYY-MM-DD.md`

### Step 4: ファイル更新・保存
- 本日報告したCVE IDを `reported-cves.md` に追記（日付付き）
- 本日報告したAPT活動を `reported-apts.md` に追記（日付付き）
  フォーマット: グループ名 | 活動ID/キャンペーン名 | YYYY-MM-DD | 採用理由
- 本日報告したAI攻撃を `reported-ai-attacks.md` に追記（日付付き）
- 以下6ファイルを `outputs/YYYY-MM-DD/` ディレクトリに保存する:
  1. `YYYY-MM-DD-security-report.json` — Section 1〜4 全データ（必須・基本形式）
  2. `YYYY-MM-DD-security-report.txt` — 全セクション完全版（Section 1〜4）
  3. `YYYY-MM-DD-security-report-cve.txt` — Section 3: 製品別CVE
  4. `YYYY-MM-DD-security-report-zeroday-trends.txt` — Section 2: ゼロデイ・トレンド
  5. `YYYY-MM-DD-security-report-ai.txt` — Section 1: AI攻撃動向
  6. `YYYY-MM-DD-security-report-soc.txt` — Section 4: GMOイエラエSOC推奨情報
- 保存完了後、`security-report.txt`（全セクション完全版）の全文をチャットに表示する（Slackへのコピー&ペースト用）

## 出力先
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json`（基本形式・全セクション）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.txt`（全セクション完全版）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-cve.txt`（Section 3: 製品別CVE）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-zeroday-trends.txt`（Section 2: ゼロデイ・トレンド）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-ai.txt`（Section 1: AI攻撃動向）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-soc.txt`（Section 4: SOC推奨情報）
- `reported-cves.md`（追記）
- `reported-apts.md`（追記）
- `reported-ai-attacks.md`（追記）

## 出力形式の原則
- Markdownコードブロック・見出し記号・テーブル記法を使わない
- Slack貼り付けを前提としたプレーンテキスト
- 詳細は pipeline-3-weighting.md の「出力形式」セクションを参照
