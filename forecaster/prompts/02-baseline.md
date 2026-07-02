# prompts/02-baseline.md — ステージ02: ベースライン更新

## あなたの役割

`forecaster/observations/` 配下に蓄積された全観測データを集計し、
「平常状態」の統計的定義（ベースライン）を更新する。
予報はこの平常からの逸脱によって判断される。ベースラインなき予報は定量的根拠を持てない。

---

## 入力

- `forecaster/observations/` 配下の全 JSON ファイル（全履歴）
- `forecaster/knowledge/group-aliases.json`（グループ名寄せマップ・必須参照）
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

### グループ名寄せ（必須・集計前に実施）

group-activity.json の集計を行う**前に**、全 observation の `actor_group` を
正規名（canonical）へ名寄せする。名寄せなしの集計は禁止する
（同一グループが別名で分散集計され、活性化判定が構造的に発火しなくなるため）。

1. `forecaster/knowledge/group-aliases.json` を読み込み、`actor_group` を各エントリの
   `canonical` / `aliases` と照合する（完全一致を優先し、なければ大文字小文字無視で一致）。
   一致したら canonical 名に置換して集計する。
2. `group-aliases.json` が存在しない場合は、`forecaster/knowledge/attack-groups.json` の
   トップレベルキーと `aliases` を使ってフォールバック名寄せを行う。
3. どちらにも収載されていないグループは、その名前自体を canonical として扱う。
   未収載グループの一覧をチャットに報告する（`group-aliases.json` への追加は
   Issue/PR として提案する。knowledge/ の自動書き換えは禁止）。
4. `group-aliases.json` に `parent_group` が定義されているグループ（例: APT38 / Andariel /
   TraderTraitor → Lazarus Group）は、canonical 単位の行に加えて、parent_group 単位で
   週別件数を合算した統計を group-activity.json の `parent_rollups` セクションに記録する。
   `parent_rollups` の各エントリは通常行と同じフィールド構成
   （mean_per_week / stddev / sample_count / last_observed / current_week_count /
   sigma_deviation / baseline_status）に加え、合算対象の canonical 一覧を
   `member_groups` として記録する。canonical 単位の行は統合・削除しない
   （MITRE の定義に従い、Andariel=G0138・APT38=G0082 は Lazarus G0032 と別グループとして維持する）。

### 最小サンプル規定（σ算出の条件）

`sigma_deviation`（および予報側で使う逸脱σ）の算出は、以下を**両方**満たす
エントリに限る:

- 観測期間（`_baseline_period_days`）が14日以上
- 非ゼロ観測単位が3以上（グループ: 観測件数が1件以上あった**週**が3週以上、
  Technique: 観測件数が1件以上あった**日**が3日以上）

満たさないエントリは `sigma_deviation: null` とし、`baseline_status: "not_established"` を
付与する。満たすエントリには `baseline_status: "established"` を付与する。
technique-freq.json / group-activity.json（`parent_rollups` 含む）の全エントリに
`baseline_status` を必ず記録する。

**注記（少数カウントの限界）**: 週あたり0〜1件程度の少数カウントはポアソン分布に近く、
正規近似にもとづくσは過大反応しやすい（例: 生涯1回の観測でも +1.4σ になる）。
現段階では上記の最小サンプル規定で誤検知を抑制し、将来的にはラプラス平滑化や
ポアソン上側確率にもとづく判定への移行を検討する（変更は人間レビューを経て行う）。

### 部分週バイアスの排除

- `mean_per_week` / `stddev` は**完結週のみ**（月曜起算で7日分すべてが集計対象期間に
  含まれる週）から算出する。進行中の当週および期間端の欠け週は平均・標準偏差に含めない。
- `current_week_count` は当週（月曜起算）の実観測件数をそのまま記録する。
- σ比較は日割り換算で行う:
  `current_week_prorated = current_week_count × 7 ÷ 当週経過日数`（当週月曜〜当日の日数）、
  `sigma_deviation = (current_week_prorated - mean_per_week) / stddev`。
  `current_week_prorated` も各エントリに記録する。
- 当週経過日数が3日未満の場合、日割り倍率が大きく過大評価になりやすいため、
  `sigma_deviation` は算出してよいが `sigma_note: "week_early_provisional"` を付与し、
  参考値であることを明示する。

### technique-freq.json の更新

各 Technique ID について:
1. 集計対象期間内の全 observations から当該 Technique が登場した日付を収集する。
2. 日別出現件数の配列を作る（登場しなかった日は 0 として含める）。
3. `mean_per_day` = 日別件数の平均
4. `stddev` = 日別件数の標準偏差（母標準偏差）
5. `sample_count` = 観測オブジェクトへの登場総回数
6. `last_observed` = 最後に登場した observed_date
7. `baseline_status` = 「最小サンプル規定」に従い `"established"` / `"not_established"`

更新後の `_last_updated` に今日の日付（YYYY-MM-DD）を設定する。

### group-activity.json の更新

各 actor_group（null 以外・**名寄せ後の canonical 単位**）について:
1. 集計対象期間内の当該グループの観測数を週単位で集計する。
2. `mean_per_week` = 完結週の週別件数の平均（「部分週バイアスの排除」参照）
3. `stddev` = 完結週の週別件数の標準偏差
4. `sample_count` = 観測オブジェクトへの登場総回数
5. `last_observed` = 最後に登場した observed_date
6. `current_week_count` = 当週（月曜起算）の観測件数、`current_week_prorated` = 日割り換算値
7. `sigma_deviation` = `(current_week_prorated - mean_per_week) / stddev`
   （stddev が 0 の場合、または「最小サンプル規定」を満たさない場合は null）
8. `baseline_status` = 「最小サンプル規定」に従い `"established"` / `"not_established"`
9. `parent_group` が定義されているグループの合算統計を `parent_rollups` に記録する
   （「グループ名寄せ」の手順4参照）

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

> 参照実装: `scripts/regen_baseline.py`（本手順の決定的な再集計スクリプト。
> `python3 scripts/regen_baseline.py` で全観測データから両ファイルを再生成できる。
> 手動集計との差異が出た場合はスクリプト側の結果を優先し、ルール変更時は両方を更新する）

1. `forecaster/observations/` を再帰的に読み込み、全 observation を収集する。
2. 当日から90日前の日付を算出し、対象期間外を除外する。
3. `forecaster/knowledge/group-aliases.json` を読み込み、actor_group を canonical へ名寄せする
   （未収載グループはチャットに報告する）。
4. technique-freq.json を算出・更新する（baseline_status 付与を含む）。
5. group-activity.json を算出・更新する（canonical 行 + `parent_rollups`、
   baseline_status 付与、部分週の日割り換算を含む）。
6. 有効性判定を出力する。
7. 処理件数（集計 observation 数、更新 Technique 数、更新グループ数、名寄せで統合された
   グループ数、baseline_status: "not_established" の件数）をチャットに報告する。
