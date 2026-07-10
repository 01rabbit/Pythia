---
name: forecast-verification
description: 攻撃予報の精度検証タスク（毎週火曜・木曜 12:00 JST に実行）
---

あなたは攻撃予報の精度を検証するエージェントです。

**本スキルはラッパーである。検証の手順・判定・記録形式の実体（単一手順書）は
`forecaster/prompts/04-verify.md` に一本化されている。**
判定ルールの正典（M1〜M4・教訓1〜13・尺度ロンダリング防止ガード・確度適用条件）は
`pipeline-forecast-verification.md` である。

## 実行手順

### Step 1: 04-verify.md を読み実行する
`forecaster/prompts/04-verify.md` を読み込み、その「実行手順」（入力読み込み → 検証対象列挙 →
CISA KEV JSON照会 → 判定 → 発行ルール遵守チェック → verification/YYYY-MM.json 更新 →
monthly_summary 更新 → observations 更新 → バイアス分析 → 週次検証レポート作成）を
記載順にそのまま実行する。判定基準・記録形式に関する詳細は 04-verify.md および
pipeline-forecast-verification.md を正典として参照し、本ファイルでは重複定義しない。

### Step 2: 変更を確認する
04-verify.md の実行によって変更されるのは以下のみであることを確認する:

- `forecaster/verification/YYYY-MM.json`（月次ファイルへの追記・確定更新）
- `forecaster/verification/YYYY-MM-DD-verification.md`（週次検証レポート・実行日付）
- `forecaster/verification/retrieval-calibration.json`（retrieval 較正データの増分追記・
  04-verify.md 手順8c・design §8）
- `forecaster/observations/` 配下の対象 observations の `verified_outcome` /
  `related_forecast_id` **の2フィールドのみ**

上記以外のファイル（knowledge/・baseline/・outputs/・予報ファイル・pipeline-*.md 等）への
変更が発生していないことを確認する。発生していた場合は実行手順の誤りとして扱い、
対象外ファイルへの変更を破棄する。

### Step 3: ブランチ作成 → コミット → PR発行
1. ブランチ名: `verify/YYYY-MM-DD`（YYYY-MM-DDは実行日）
2. 変更ファイル: Step 2 で確認した範囲のみ
   （`forecaster/verification/YYYY-MM.json` /
   `forecaster/verification/YYYY-MM-DD-verification.md` /
   `forecaster/verification/retrieval-calibration.json` /
   対象 observations の `verified_outcome`・`related_forecast_id`）
3. コミットメッセージ: `"forecast verification: YYYY-MM-DD"`
4. main へのPRを発行する
   - PRタイトル: `"攻撃予報 精度検証: YYYY-MM-DD"`
   - PR本文: 検証結果のサマリー（全予報統合の的中率・確度別キャリブレーション・
     主なバイアス・発行ルール遵守チェック結果）を記載
5. PRのURLをチャットに表示して完了

## 重要ルール
- 変更してよいのは `forecaster/verification/*.json` および
  `forecaster/verification/*.md`（週次検証レポート）と、
  observations の `verified_outcome` / `related_forecast_id` フィールドのみ。
  それ以外のファイルは変更しない。
- main への直接pushは行わない（必ずPR経由）。
- 判定を甘くする方向の変更（的中条件の緩和・トラック移動・確定義務の回避等）は
  04-verify.md / pipeline-forecast-verification.md いずれの規則でも禁止されている。
  本スキル実行時もこれを遵守する。
