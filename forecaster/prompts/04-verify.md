# prompts/04-verify.md — ステージ04: 検証（verification）

## あなたの役割

過去の予報と、その後の実観測データを突き合わせ、的中・外れを記録する。
このステージはシステムの心臓部である。検証ループが回らなければ精度は原理的に上がらない。

既存の `pipeline-forecast-verification.md` の精度検証タスク（週2回・火曜/木曜 12:00 JST）と
連動して実行する。

---

## 実行タイミング

週2回（火曜・木曜）の `pipeline-forecast-verification.md` 精度検証タスクに続けて実行する。
または手動実行可能。

---

## 入力

1. `forecaster/forecasts/daily/` 配下の過去7日分の予報ファイル
2. `forecaster/observations/` 配下の対応期間の observations
3. `forecaster/verification/` 配下の既存検証ファイル（存在する場合）

---

## 出力

- `forecaster/verification/YYYY-MM.json`（月次ファイルに追記）
- 対象 observations の `verified_outcome` フィールドを更新

---

## 突合ルール

### 予報ごとの的中判定

各予報の `的中判定:` フィールドに記載された条件を最優先で使用する。
記載がない場合は以下の共通基準を使う（pipeline-forecast-verification.md と同一）:

| 判定 | 基準 |
|------|------|
| hit | 予報した事象を示す新規CERT勧告・ベンダーレポート・IOC公開が観測された |
| partial | 関連するが予報の核心ではない変化が観測された |
| miss | 72時間以内に関連する新規変化が確認されなかった |
| unverifiable | 週末欠落・対象期間外等で検証不可能 |

### verified_outcome の書き込み

予報に関連する observations を特定し、その `verified_outcome` フィールドに判定値を書き込む。
`related_forecast_id` フィールドに対応する予報ファイルのパスを記録する。

**このフィールドを書き込めるのは本ステージのみ。他のステージでは変更禁止。**

---

## verification/YYYY-MM.json の形式

```json
{
  "_schema_version": "1.0",
  "_month": "YYYY-MM",
  "_last_updated": "YYYY-MM-DD",
  "entries": [
    {
      "forecast_date": "YYYY-MM-DD",
      "forecast_file": "forecaster/forecasts/daily/YYYY-MM-DD.md",
      "forecast_index": 1,
      "forecast_title": "予報タイトル",
      "tier": "T1|T2|T3",
      "confidence": "high|medium",
      "outcome": "hit|partial|miss|unverifiable",
      "evidence_for_outcome": "何が確認された、または確認されなかったか（1〜2文）",
      "related_observation_ids": ["obs-YYYY-MMDD-NNN"]
    }
  ],
  "monthly_summary": {
    "total": 0,
    "hit": 0,
    "partial": 0,
    "miss": 0,
    "unverifiable": 0,
    "hit_rate_strict": null,
    "hit_rate_including_partial": null
  },
  "bias_analysis": [],
  "profile_correction_proposals": []
}
```

---

## バイアス分析と補正提案

突合が完了したら以下を分析してチャットに報告する:

### バイアス分析
- T3（新規PoC武器化）の miss 率が高い場合: 「T3予報の採用閾値を引き上げる」
- 特定グループの予測が外れ続ける場合: 「attack-groups.json の typical_tactics_order を見直す」
- 特定 tactic 遷移の外れが続く場合: 「technique-chains.json の transition_matrix を更新する」

### プロファイル補正提案（自動適用禁止）
attack-groups.json の frequency 値について、実観測に基づく補正提案を以下の形式で出力する。
人間レビュー後に `attack-groups.json` を手動で更新すること。

```
補正提案 [グループ名]:
  T1566 frequency: 0.82 → 0.87（根拠: 直近30日の観測でX/Y件が本Techniqueを使用）
```

---

## 実行手順

1. 対象期間（過去7日）の予報ファイルを読み込む。
2. 各予報の的中判定条件を確認する。
3. 対応する observations を検索し、突合判定を行う。
4. `forecaster/verification/YYYY-MM.json` に結果を記録する。
5. 対象 observations の `verified_outcome` と `related_forecast_id` を更新する。
6. バイアス分析と補正提案をチャットに出力する。
7. 月次サマリーの的中率を更新する。
8. 変更した全ファイルをコミット対象として報告する（コミット自体は行わない）。
