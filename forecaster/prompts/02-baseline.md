# prompts/02-baseline.md — ステージ02: ベースライン更新

## あなたの役割

`forecaster/observations/` 配下に蓄積された全観測データを集計し、
「平常状態」の統計的定義（ベースライン）を更新する。
予報はこの平常からの逸脱によって判断される。ベースラインなき予報は定量的根拠を持てない。

---

## 入力

- `forecaster/observations/` 配下の全 JSON ファイル（全履歴）
- 既存の `forecaster/baseline/technique-freq.json`
- 既存の `forecaster/baseline/group-activity.json`

---

## 出力

- `forecaster/baseline/technique-freq.json`（上書き更新）
- `forecaster/baseline/group-activity.json`（上書き更新）

---

## 算出ルール

### 集計対象期間
直近90日分の observations を使用する。90日未満の場合は全期間を使用し、
`_baseline_period_days` に実際の日数を記録する。

### technique-freq.json の更新

各 Technique ID について:
1. 集計対象期間内の全 observations から当該 Technique が登場した日付を収集する。
2. 日別出現件数の配列を作る（登場しなかった日は 0 として含める）。
3. `mean_per_day` = 日別件数の平均
4. `stddev` = 日別件数の標準偏差（母標準偏差）
5. `sample_count` = 観測オブジェクトへの登場総回数
6. `last_observed` = 最後に登場した observed_date

更新後の `_last_updated` に今日の日付（YYYY-MM-DD）を設定する。

### group-activity.json の更新

各 actor_group（null 以外）について:
1. 集計対象期間内の当該グループの観測数を週単位で集計する。
2. `mean_per_week` = 週別件数の平均
3. `stddev` = 週別件数の標準偏差
4. `sample_count` = 観測オブジェクトへの登場総回数
5. `last_observed` = 最後に登場した observed_date
6. `current_week_count` = 当週（月曜起算）の観測件数
7. `sigma_deviation` = `(current_week_count - mean_per_week) / stddev`（stddev が 0 の場合は null）

---

## ベースライン有効性の判定

集計後、以下の有効性フラグをチャットに報告する:

| 条件 | 報告メッセージ |
|------|--------------|
| `_baseline_period_days` < 14 | 警告: ベースライン期間が14日未満。予報の定量的根拠として不十分。 |
| 14 <= days < 30 | 注意: ベースライン期間が30日未満。参考値として使用可能だが精度は低い。 |
| 30 <= days < 90 | 有効: ベースライン期間 N日。予報生成に使用可能。 |
| days >= 90 | 安定: 90日以上の安定ベースライン。 |

---

## 実行手順

1. `forecaster/observations/` を再帰的に読み込み、全 observation を収集する。
2. 当日から90日前の日付を算出し、対象期間外を除外する。
3. technique-freq.json を算出・更新する。
4. group-activity.json を算出・更新する。
5. 有効性判定を出力する。
6. 処理件数（集計 observation 数、更新 Technique 数、更新グループ数）をチャットに報告する。
