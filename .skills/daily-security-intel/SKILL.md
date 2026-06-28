---
name: daily-security-intel
description: 毎日定時に実行するセキュリティインテリジェンス収集・重みづけ・レポート生成タスク
---

あなたは日次セキュリティインテリジェンスパイプラインを実行するエージェントです。
リポジトリルート直下の各ファイルを参照して作業を進めること。

## 実行前に必ず読むファイル
以下のファイルを順番に読み込み、内容に従って作業を進めること:
1. reported-cves.md — 既報CVEリスト
2. reported-apts.md — 既報APT活動リスト
3. reported-ai-attacks.md — 既報AI攻撃リスト
4. pipeline-1-cve.md — Step 1 CVE調査ルール
5. pipeline-1b-apt.md — Step 1b APT活動調査ルール
6. pipeline-2-trends.md — Step 2 動向収集ルール
7. pipeline-3-weighting.md — Step 3 重みづけ・出力ルール
8. pipeline-output-schema.md — JSONスキーマ定義

## 実行手順

### Step 0: 時刻確認・期間確定
- 現在時刻（JST）を取得する
- 調査対象期間: 実施日前日 07:00 JST 〜 実施日 07:00 JST（固定ウィンドウ）

### Step 1: CVE調査（pipeline-1-cve.md に従う）
- NVD / CISA KEV / GitHub Advisory / ベンダーアドバイザリを横断検索
- 期間内に A〜H の変化が確認できるCVEのみ収集
- reported-cves.md と照合し、既報かつ変化なしは除外
- 除外基準はフラグ付け（足切りしない）

### Step 1b: APT活動調査（pipeline-1b-apt.md に従う）※Step 1 と並行実行
- Mandiant / MSTIC / CrowdStrike / Unit 42 / CISA合同勧告等を横断検索
- 期間内に P〜W の変化が確認できる活動のみ収集
- reported-apts.md と照合し、既報かつ変化なしは除外
- 除外基準はフラグ付け（足切りしない）

### Step 1c: AI攻撃調査（pipeline-ai-1.md に従う）※Step 1・Step 1b と並行実行
- MITRE ATLAS / OWASP GenAI / arXiv cs.CR / AI Incident Database / HiddenLayer 等を横断検索
- Temporal Burst Filtering（48時間以内に3件以上の独立ソース）を適用
- reported-ai-attacks.md と照合し、既報かつ変化なしは除外

### Step 2: 動向収集（pipeline-2-trends.md に従う）
- 英語ソース: BleepingComputer / The Hacker News / SecurityWeek / Mandiant 等
- 日本語ソース（必須）: Security NEXT / JPCERT/CC 注意喚起 / IPA重要情報 / ScanNetSecurity
- APT補完ソース: MSTIC / CrowdStrike / Unit 42 / NISC / 警察庁サイバー警察局
- 24時間窓内の記事・更新のみ対象
- 件数制限なし、全件ストック

### Step 3: 重みづけ・JSON生成・テキスト変換（pipeline-3-weighting.md・pipeline-ai-2.md に従う）
- Step 3 実行前に pipeline-forecast-verification.md を読むこと
- CVE: 軸1（技術深刻度）× 軸2（実環境影響）で評価
- APT: 軸P（信頼性・活動深刻度）× 軸Q（キャンペーン規模・影響範囲）で評価
- AI攻撃: 軸X（実証・悪用深刻度）× 軸Y（影響範囲・実害）で評価（Temporal Burst Filtering適用）
- 日本語ソースが確認できたCVEは参考A昇格トリガーを自動適用
- 出力セクション構成（常時全セクション）:
    ゼロデイ特報 / 本編（CVE）/ 参考A（国内）/ 参考B（国際先行）
    / APT活動-本編 / APT活動-注目動向 / 攻撃予報
    / AI攻撃-本編 / AI攻撃-参考B / AI攻撃-参考A / AI攻撃日次サマリー
    / SOC推奨情報 / 除外サマリー

**JSON-first出力手順**:
1. pipeline-output-schema.md のスキーマに従い security-report.json を生成する
2. JSONの内容を pipeline-3-weighting.md・pipeline-report-modes.md・pipeline-ai-2.md・pipeline-soc-recommend.md のテンプレートに従い以下5種のプレーンテキストファイルに変換する:
   - security-report.txt: 全セクション完全版（Section 1〜4）
   - security-report-cve.txt: Section 3（製品別CVE）— ゼロデイ特報・本編CVE・参考A・参考B・除外CVE・集計CVE
   - security-report-zeroday-trends.txt: Section 2（ゼロデイ・トレンド）— ゼロデイ特報・APT活動・攻撃予報・除外APT・集計APT
   - security-report-ai.txt: Section 1（AI攻撃動向）— 本編・参考B・参考A・週次サマリー・除外AI攻撃・集計AI攻撃
   - security-report-soc.txt: Section 4（SOC推奨情報）— 高/中/低優先度・除外・集計

### Step 4: ファイル更新・保存・コミット
- 本日報告したCVE IDを reported-cves.md に追記（日付付き）
- 本日報告したAPT活動を reported-apts.md に追記（日付付き）
  フォーマット: グループ名 | 活動ID/キャンペーン名 | YYYY-MM-DD | 採用理由
- 本日報告したAI攻撃を reported-ai-attacks.md に追記（日付付き）
  フォーマット: インシデント名/CVE等 | カテゴリ | YYYY-MM-DD | 採用理由
- 出力先ディレクトリ outputs/YYYY-MM-DD/ を作成する
- 以下6ファイルを outputs/YYYY-MM-DD/ に保存する:
  - YYYY-MM-DD-security-report.json（全セクション構造化JSON）
  - YYYY-MM-DD-security-report.txt（全セクション・完全版）
  - YYYY-MM-DD-security-report-cve.txt（Section 3: 製品別CVE）
  - YYYY-MM-DD-security-report-zeroday-trends.txt（Section 2: ゼロデイ・セキュリティトレンド）
  - YYYY-MM-DD-security-report-ai.txt（Section 1: AI攻撃動向）
  - YYYY-MM-DD-security-report-soc.txt（Section 4: SOC推奨情報）
- 変更されたファイル（reported-cves.md, reported-apts.md, reported-ai-attacks.md, outputs/YYYY-MM-DD/以下）を
  git add → git commit → git push でブランチにコミットする
  コミットメッセージ例: "daily report: YYYY-MM-DD"

## 出力形式の原則
- YYYY-MM-DD-security-report.json: pipeline-output-schema.md のスキーマに従った構造化JSON（AI分析・機械処理用）
- 以下5種のテキストファイルはJSONから変換（プレーンテキスト・Markdownコードブロック・見出し記号・テーブル記法を使わない）:
  - YYYY-MM-DD-security-report.txt: 全セクション完全版（Section 1〜4）
  - YYYY-MM-DD-security-report-cve.txt: Section 3 製品別CVE（ゼロデイ特報・本編・参考A・参考B・除外CVE）
  - YYYY-MM-DD-security-report-zeroday-trends.txt: Section 2 ゼロデイ・トレンド（ゼロデイ特報・APT・攻撃予報・除外APT）
  - YYYY-MM-DD-security-report-ai.txt: Section 1 AI攻撃動向（本編・参考B・参考A・週次サマリー・除外AI攻撃）
  - YYYY-MM-DD-security-report-soc.txt: Section 4 SOC推奨情報（高/中/低優先度・除外）
- 詳細は pipeline-3-weighting.md の「出力形式」セクションを参照
