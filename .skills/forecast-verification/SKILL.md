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
- ただし `forecast_class: slow_7d`（検証窓: slow_7d）の予報は最大14日遡って走査する（M2・7日窓のため）
- 各レポートの【攻撃予報（48〜72時間）】セクションにある予報を全て抽出する
- 各予報の `outcome_channel`（観測出口クラス E1〜E4）・`forecast_class`（fast_72h / slow_7d）・`window_hours` を必ず読み取る

### Step 2: pipeline-forecast-verification.md を読む
- 的中判定基準（的中 / 部分的中 / 外れ / 検証不能）を確認する
- 各予報に記載された「的中判定:」条件を確認する

### Step 3: 的中判定
- 各予報について、その後のレポートファイルを参照して判定する
- 予報に「的中判定:」条件が記載されている場合はその条件を優先する
- 未記載の場合は pipeline-forecast-verification.md の共通基準を使う
- 検証窓（fast_72h=72時間 / slow_7d=168時間以上）内の後続レポートに根拠が見つからない場合は「外れ」または「検証不能」とする

#### M4: KEV変化の的中判別（再登録は非的中）
- 観測出口クラスが E1（KEV初回追加）の予報は、後続レポートのKEV状態を発行時 `kev_snapshot` と差分比較する
- 的中とするのは以下のみ:
  - `date_added` が検証イベントと一致（初回追加）
  - `ransomware_flag` が Unknown→Known に変化、または新規参照の追加
- `date_added` 同一・ランサムフラグ同一・新規参照なしの再公開（再登録）は **非的中**（教訓13）
- 固定一次ソース（CISA KEV / JPCERT/CC 等）が未公開で二次ソース（PSIRT等）のみ確認できる場合は「外れ」ではなく「検証不能（固定ソース確認待ち）」とする

#### M2: トラック別集計と確定義務
- 主指標は「全予報統合（fast_72h + slow_7d 合算）」の的中率とする（M2ガード1・72hトラック単独を主指標に昇格させない）
- `forecast_class` 別の内訳は補助として併記する
- `slow_7d` 予報は `deadline_date`（発行+7日）を含む検証で必ず確定する。期限超過の未確定は自動で「外れ」に倒す（M2ガード2・保留の永続化禁止）
- 発行時の `forecast_class` と検証時のトラックが一致していることを突合する（M2ガード3・トラック移動禁止）
- カバレッジ（発行予報数 / 候補主題数・見送りクラス数）を週次サマリーに記録する（M1の剪定可視化）

### Step 4: 検証結果ファイルを作成
以下のパスにMarkdownファイルを作成する:
  verification/YYYY-MM-DD-verification.md  （YYYYMMDDは実行日）

ファイル内容は pipeline-forecast-verification.md のフォーマットに従う。
ただし出力形式はプレーンテキストではなくMarkdownで記述する（PR上での可読性優先）。

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
