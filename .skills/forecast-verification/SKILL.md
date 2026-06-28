---
name: forecast-verification
description: 攻撃予報の精度検証タスク（毎週火曜・木曜 12:00 JST に実行）
---

あなたは攻撃予報の精度を検証するエージェントです。
pipeline-forecast-verification.md の手順に厳密に従って検証を行い、
結果をMarkdownファイルとして保存しGitHub PRを発行してください。

## 実行手順

### Step 1: 検証対象ファイルの読み込み
- outputs/ フォルダから、実行日から過去7日分の security-report.txt を全件読み込む
- 各レポートの【攻撃予報（48〜72時間）】セクションにある予報を全て抽出する

### Step 2: pipeline-forecast-verification.md を読む
- 的中判定基準（的中 / 部分的中 / 外れ / 検証不能）を確認する
- 各予報に記載された「的中判定:」条件を確認する

### Step 3: 的中判定
- 各予報について、その後のレポートファイルを参照して判定する
- 予報に「的中判定:」条件が記載されている場合はその条件を優先する
- 未記載の場合は pipeline-forecast-verification.md の共通基準を使う
- 72時間窓内の後続レポートに根拠が見つからない場合は「外れ」または「検証不能」とする

### Step 4: 検証結果ファイルを作成
以下のパスにMarkdownファイルを作成する:
  verification/YYYY-MM-DD-verification.md  （YYYYMMDDは実行日）

ファイル内容は pipeline-forecast-verification.md のフォーマットに従う。
ただし出力形式はSlack用プレーンテキストではなくMarkdownで記述する（PR上での可読性優先）。

### Step 5: ブランチ作成 → コミット → PR発行
1. ブランチ名: verify/YYYY-MM-DD
2. 変更ファイル: verification/YYYY-MM-DD-verification.md
3. コミットメッセージ: "forecast verification: YYYY-MM-DD"
4. main へのPRを発行する
   - PRタイトル: "攻撃予報 精度検証: YYYY-MM-DD"
   - PR本文: 検証結果のサマリー（総予報数・的中率・主なバイアス）を記載
5. PRのURLをチャットに表示して完了

## 重要ルール
- verification/ 以外のファイルは変更しない
- main への直接pushは行わない（必ずPR経由）
