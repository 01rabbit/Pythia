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

### Step 4: PRをmainへマージする（2026-09-01 ルール化・01rabbit指示）
PRを発行して終わりにせず、**基本的にそのままmainへマージするところまで実行する**
（レビュー待ちで放置しない）。手順:

1. CI（`validate` 等のチェック）の結果を確認する。
2. **CIが緑、またはチェックが存在しない場合**: そのままマージする
   （マージ方式は直近のmainのコミット履歴の慣習に合わせる。squash-with-PR-number形式
   〈"タイトル (#NNN)"〉が直近の主流であればそれに合わせる）。
3. **CIが赤い場合**: 機械的にマージせず、まず失敗が本PRの変更に起因するか切り分ける。
   - 本PRが変更していないファイルに対する失敗で、baseブランチの同一ファイルに対して
     直接チェックを実行しても同じ失敗が再現する場合は「本PR起因ではない」と判断してよい。
   - 本PR起因ではないと判断した場合、PRへ根拠（何が失敗しているか・なぜ本PR起因でないか・
     再現確認の方法）をコメントで残し、GitHub上でマージがブロックされていない
     （`mergeable_state` が `blocked` ではない）ことを確認した上でマージする。
     未追跡の欠陥であれば別途Issueを起票し、PRコメントとマージコミットメッセージから
     参照する。
   - 本PR自体の変更が原因の失敗（Step 2 の許可範囲を超えた変更・観測/検証JSONの
     不整合等）の場合はマージせず、原因を修正して再コミットしてから改めてこの手順を行う。
   - GitHub側でマージがブロックされている場合（`mergeable_state: blocked`）は、
     必須チェック・必須レビューを無理に回避せず、状況をチャットで報告して指示を仰ぐ。
4. マージ後、PRのURLとマージ結果（コミットSHA・マージ方式）をチャットに表示して完了。

## 重要ルール
- 変更してよいのは `forecaster/verification/*.json` および
  `forecaster/verification/*.md`（週次検証レポート）と、
  observations の `verified_outcome` / `related_forecast_id` フィールドのみ。
  それ以外のファイルは変更しない。
- main への直接pushは行わない（必ずPR経由）。ただし **PRを開いた後は上記Step 4に従い
  最終的にmainへマージするところまでを本スキルの完了条件とする**（PRを開いたまま
  レビュー待ちで放置することを標準としない）。
- 判定を甘くする方向の変更（的中条件の緩和・トラック移動・確定義務の回避等）は
  04-verify.md / pipeline-forecast-verification.md いずれの規則でも禁止されている。
  本スキル実行時もこれを遵守する。
