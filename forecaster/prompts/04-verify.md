# prompts/04-verify.md — ステージ04: 検証（verification）★単一手順書

## あなたの役割

過去の予報と、その後の実観測データを突き合わせ、的中・外れを記録する。
このステージはシステムの心臓部である。検証ループが回らなければ精度は原理的に上がらない。

**本ファイルは検証の単一手順書（実体）である。**
週次精度検証スキル（`.skills/forecast-verification/SKILL.md`・毎週火曜/木曜 12:00 JST）は
本ファイルを読み込んで実行するラッパーであり、検証の手順・判定・記録形式はすべて本ファイルに一意化する。
判定ルールの正典（M1〜M4・教訓1〜13・尺度ロンダリング防止ガード・確度適用条件）は
`pipeline-forecast-verification.md` であり、本ファイルと齟齬がある場合は同ファイルを優先する。

---

## 実行タイミング

毎週火曜・木曜 12:00 JST（`.skills/forecast-verification/SKILL.md` 経由の自動実行）。
手動実行も可能。

---

## 入力

0. `forecaster/forecasts/daily/YYYY-MM-DD.json`（予報サイドカーJSON）— 存在する場合は
   検証の**一次入力**とする。`forecaster/forecasts/daily/YYYY-MM-DD.md` は当該日付の
   サイドカーJSONが存在しない場合のみ一次入力として使用し、サイドカーJSONが存在する日は
   Markdownを補足参照（文脈確認用）に留める。
1. `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json` — 実行日から過去14日分。
   **検証の一次入力はJSONとする。** M4判定に必須の `kev_snapshot` / `anchor` /
   `forecast_class_rationale` / `deadline_date` はJSON専用出力（pipeline-output-schema.md 参照）
   のため、`.txt` を検証入力に使ってはならない。
2. `forecaster/forecasts/daily/YYYY-MM-DD.md` — 実行日から過去14日分の予報ファイル。
3. `forecaster/observations/` 配下の対応期間の observations。
4. `forecaster/verification/` 配下の既存検証ファイル（未確定エントリの再判定に使う）。
5. **CISA KEV カタログJSON（直接照会・必須）**:
   `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   E1（KEV初回追加）の判定、および E4 で KEV 参照の更新が判定材料になる予報は、
   自レポート網の記載のみに依存せず本カタログを直接照会して判定する
   （自レポートの拾い漏れによって真の的中が「外れ」に化けることを防ぐ）。

検証対象の遡及範囲: fast_72h トラックは過去7日分で足りるが、
slow_7d トラック（7日窓）は最大14日遡って走査する（M2）。

---

## 出力（このステージが変更してよいファイル）

- `forecaster/verification/YYYY-MM.json`（月次ファイルに追記）
- `forecaster/verification/YYYY-MM-DD-verification.md`（週次検証レポート・実行日付）
- 対象 observations の `verified_outcome` / `related_forecast_id` **の2フィールドのみ**
  （observations の他フィールドの変更は禁止）

上記以外のファイル（knowledge/・baseline/・outputs/・予報ファイル・pipeline-*.md 等）は変更しない。

---

## 突合ルール

### 予報ごとの的中判定

各予報の `hit_criteria`（テキストでは「的中判定:」行）に記載された条件を最優先で使用する。
**発行済み予報の的中条件を検証時に緩めることは禁止**（原則D・教訓12）。
記載がない場合は以下の共通基準を使う（pipeline-forecast-verification.md と同一）:

| 判定 | 基準 |
|------|------|
| hit（的中） | 予報した観測出口クラス（E1〜E4）の一次イベントが検証窓内に確認された |
| hit（KEV起点） | KEV登録後72時間以内に対象製品へのスキャン増加・侵害試行・悪用PoC公開がCERTまたはベンダーレポートで確認された |
| partial（部分的中） | 関連するが予報の核心ではない変化（例: 新CVEの派生、別グループの悪用）が確認された |
| miss（外れ） | 予報した一次イベントが検証窓内（fast_72h=72時間 / slow_7d=168時間以上）に確認されなかった |
| unverifiable（検証不能） | 対象期間外・週末のレポート欠落・検証窓未完了・固定一次ソース確認待ち等で検証不可能 |

### M2: トラック別検証と確定義務

- 各予報の `forecast_class`（fast_72h / slow_7d）・`window_hours`・`deadline_date` をJSONから読み取る。
- **主指標は「全予報統合（fast_72h + slow_7d 合算）」の的中率**とする（M2ガード1）。
  トラック別内訳は補助であり、主指標に昇格させない。
- slow_7d 予報は `deadline_date`（発行+7日）を含む検証で必ず確定する。
  **期限超過の未確定は自動で miss に倒す**（M2ガード2・保留の永続化禁止）。
  この場合 `evidence_for_outcome` に「期限超過自動外れ」と明記する。
- 発行時の `forecast_class` / `forecast_class_rationale` と検証時のトラックを突合し、
  発行後のトラック移動が起きていないことを確認する（M2ガード3・トラック移動は禁止。
  検出した場合は違反として bias_analysis に記録する）。
- 過去の検証で unverifiable（検証窓未完了・固定ソース確認待ち）とした既存エントリは、
  窓が満了していれば今回の検証で必ず hit / partial / miss に確定する。

### M4: KEV差分判定（E1・再登録は非的中）

`outcome_channel: E1` の予報は以下の手順で判定する:

1. CISA KEV JSON を直接取得し、当該CVEのエントリを検索する。
2. 発行時 `kev_snapshot`（`date_added` / `ransomware_flag` / `reference_set`）との差分を計算する。
3. 的中を構成するのは以下のみ:
   - `dateAdded` が当該検証イベントと一致する**初回追加**（KEVカタログ上の新規追加）
   - `Known Ransomware Campaign Use` の Unknown→Known 変化、または新規勧告/参照の追加
4. `dateAdded` 同一・ランサムフラグ同一・新規参照なしの再公開（内容変化なしの「再登録」）は
   **非的中**として扱う（教訓13）。
5. 差分結果を検証エントリの `kev_snapshot_diff` に記録する。

E4（PoC公開）の予報でも、KEV の参照セットへの PoC/エクスプロイト追加が判定材料になる場合は
同様に CISA KEV JSON を直接照会して確認する。

### 確度キャリブレーション算出（目標帯乖離判定・Brierスコア）

`monthly_summary.by_confidence` の各確度（high/medium/low）について以下を算出する
（目標帯・代表確率の定義は pipeline-forecast-verification.md「確度の定義」参照）:

1. **目標帯乖離判定**: `hit_rate_including_partial` を目標帯（高0.70-1.00／中0.40-0.70／
   低0.00-0.40）と比較し、`calibration_status` に `within_target` / `deviation_high`
   （帯より上振れ）/ `deviation_low`（帯より下振れ）を設定する。該当確度の `total` が
   0件の場合は `calibration_status: null`（判定不能）とする。
2. **Brierスコア算出**: 代表確率（高=0.75／中=0.55／低=0.30）を予測確率 `p` とし、
   各予報の実績を2値結果 `o`（hit=1・partial=0.5・miss=0。unverifiableは対象外）として、
   `(p - o)^2` を確度内の対象予報について平均し `brier_score` に記録する
   （0に近いほど較正が良い。0.25はランダム相当の目安）。
3. **2ヶ月連続乖離の検出**: 当月と前月の `verification/YYYY-MM.json` を比較し、
   同一確度で2ヶ月連続 `deviation_high` または `deviation_low` が検出された場合、
   `bias_analysis` に確度適用条件の見直し提案を起票する（下記バイアス分析参照）。
   前月ファイルが存在しない、または前月の当該確度が `total: 0` の場合は連続判定をスキップする。

### 固定一次ソース＋エスカレーション規則

観測出口クラス（E1〜E4）の一次データソースは pipeline-forecast-verification.md の表で
固定されており、判定者の裁量で別ソースを足さない（「曖昧なら的中にしておく」裁量を奪う）。
ただし固定ソース（例: JPCERT）が未公開かつ二次ソース（PSIRT等）で真イベントが確認できる場合は、
miss ではなく **unverifiable（固定ソース確認待ち）**と判定する
（偽部分的中を偽missに置換しないため）。次回検証で固定ソースを再確認して確定する。

### 発行ルール遵守チェック（全予報・必須）

検証対象期間の各予報発行日について以下を確認し、違反を `bias_analysis` に記録する。
違反があっても当該予報の的中判定自体は発行時の記載どおり実施する（判定の甘辛には影響させない）:

1. **1日の予報発行数が最大2件以内か**（pipeline-forecast-verification.md 絞り込みルール）
2. 各予報に `hit_criteria`（的中判定条件）が記載されているか
3. 各予報に `outcome_channel`（観測出口クラス E1〜E4）が記載されているか
4. 各予報に `forecast_class` が記載され、slow_7d の場合は `deadline_date` が記載されているか

### verified_outcome の書き込み

予報に関連する observations を特定し、その `verified_outcome` フィールドに判定値を書き込む
（スキーマの enum は `hit` / `partial` / `miss` / `null`。unverifiable の場合は null のまま維持し、
確定後の検証で書き込む）。
`related_forecast_id` フィールドに対応する予報ファイルのパスを記録する。

**この2フィールドを書き込めるのは本ステージのみ。他のステージでは変更禁止。**

---

## verification/YYYY-MM.json の形式（v1.1）

**適用範囲**: 新形式フィールド（`forecast_class` / `window_hours` / `deadline_date` /
`outcome_channel` / `kev_snapshot_diff`）は**新規エントリから適用**する。
記録済みの過去エントリ（2026-06.json の既存エントリ等）への遡及的なフィールド追加・形式改変は禁止。
ただし unverifiable（未確定）で記録済みのエントリの `outcome` / `evidence_for_outcome` を
窓満了後に確定させる更新は、改変ではなく確定義務（M2ガード2）であり必ず行う。
確定済み（hit / partial / miss）の過去エントリは変更しない。

```json
{
  "_schema_version": "1.1",
  "_month": "YYYY-MM",
  "_last_updated": "YYYY-MM-DD",
  "entries": [
    {
      "forecast_date": "YYYY-MM-DD",
      "forecast_file": "forecaster/forecasts/daily/YYYY-MM-DD.md",
      "forecast_index": 1,
      "forecast_title": "予報タイトル",
      "tier": "T1|T2|T3",
      "confidence": "high|medium|low",
      "forecast_class": "fast_72h|slow_7d",
      "window_hours": 72,
      "deadline_date": "YYYY-MM-DD",
      "outcome_channel": "E1|E2|E3|E4",
      "outcome": "hit|partial|miss|unverifiable",
      "kev_snapshot_diff": {
        "cve_id": "CVE-YYYY-NNNNN",
        "checked_at": "YYYY-MM-DD",
        "date_added_change": "none|initial_add",
        "ransomware_flag_change": "none|unknown_to_known",
        "new_references": []
      },
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
    "hit_rate_including_partial": null,
    "by_confidence": {
      "high":   { "total": 0, "hit": 0, "partial": 0, "miss": 0, "unverifiable": 0, "hit_rate_strict": null, "hit_rate_including_partial": null, "target_band": "0.70-1.00", "calibration_status": null, "representative_probability": 0.75, "brier_score": null },
      "medium": { "total": 0, "hit": 0, "partial": 0, "miss": 0, "unverifiable": 0, "hit_rate_strict": null, "hit_rate_including_partial": null, "target_band": "0.40-0.70", "calibration_status": null, "representative_probability": 0.55, "brier_score": null },
      "low":    { "total": 0, "hit": 0, "partial": 0, "miss": 0, "unverifiable": 0, "hit_rate_strict": null, "hit_rate_including_partial": null, "target_band": "0.00-0.40", "calibration_status": null, "representative_probability": 0.30, "brier_score": null }
    },
    "by_track": {
      "fast_72h": { "total": 0, "hit": 0, "partial": 0, "miss": 0, "unverifiable": 0 },
      "slow_7d":  { "total": 0, "hit": 0, "partial": 0, "miss": 0, "unverifiable": 0, "deadline_auto_miss": 0 }
    }
  },
  "bias_analysis": [],
  "profile_correction_proposals": []
}
```

フィールド補足:

- `deadline_date`: fast_72h は発行+3日（72時間窓の満了日）、slow_7d は発行時JSONの
  `deadline_date`（発行+7日）を転記する。期限管理と期限超過自動missの判定に使う。
- `kev_snapshot_diff`: `outcome_channel` が E1 以外、または発行時 `kev_snapshot` が存在しない
  場合は `null` とする。
- `by_confidence`: **確度別的中率のキャリブレーション表**。確度「高」が「中」より的中率で
  劣後していないかを毎回確認する（下記バイアス分析参照）。各確度には目標確率帯
  （`target_band`: 高=0.70-1.00／中=0.40-0.70／低=0.00-0.40、
  pipeline-forecast-verification.md「確度の定義」参照）を固定値として記録し、
  `hit_rate_including_partial` が帯の外にあれば `calibration_status` に
  `deviation_high`（目標帯より上振れ）または `deviation_low`（目標帯より下振れ）を、
  帯内であれば `within_target` を設定する。`representative_probability`
  （高=0.75／中=0.55／低=0.30固定）と実際の hit/partial/miss 結果からBrierスコア
  （下記「キャリブレーション算出」参照）を算出し `brier_score` に記録する。
- `by_track`: **補助内訳のみ**（M2ガード1）。主指標（トップレベルの hit_rate）に昇格させない。

---

## バイアス分析と補正提案

突合が完了したら以下を分析し、週次検証レポートとチャットに報告する:

### バイアス分析
- T3（新規PoC武器化）の miss 率が高い場合: 「T3予報の採用閾値を引き上げる」
- 特定グループの予測が外れ続ける場合: 「attack-groups.json の typical_tactics_order を見直す」
- 特定 tactic 遷移の外れが続く場合: 「technique-chains.json の transition_matrix を更新する」
- **キャリブレーション（確度別的中率）**: 確度「高」の的中率（部分的中含む）が確度「中」を
  下回る場合、確度較正の異常として `bias_analysis` に記録し、「確度: 高」適用条件
  （定量ゲートD含む）の見直しを提案する。見直しは確度付与の入口の厳格化に限り、
  的中判定基準（hit_criteria）には一切触れない（M3の原則）。
- **キャリブレーション見直し手順（2ヶ月連続乖離）**: 「確度キャリブレーション算出」で
  同一確度が2ヶ月連続で `deviation_high` または `deviation_low` と判定された場合、
  `bias_analysis` に以下の形式で確度適用条件の見直し提案を起票する:

  ```
  確度較正見直し提案 [確度: high|medium|low]:
    2ヶ月連続 [deviation_high|deviation_low]（YYYY-MM: 実績X% / YYYY-MM: 実績Y%、目標帯Z%）
    提案: [適用条件A〜D・定量ゲートDの具体的な見直し方向]
  ```

  **禁止事項（発行済み予報の再採点禁止）**: この見直しは将来発行する予報の確度**適用条件**
  にのみ適用し、`verification/YYYY-MM.json` に記録済みの過去エントリの `confidence` /
  `outcome` を遡って書き換えることは禁止する（原則D・pipeline-forecast-verification.md
  「確度キャリブレーション運用」参照）。1ヶ月のみの乖離は記録に留め、見直し起票は行わない。
- **発行ルール違反**: 発行ルール遵守チェックで検出した違反（1日3件以上の発行・
  hit_criteria / outcome_channel / forecast_class の欠落・発行後のトラック移動）を
  `bias_analysis` に記録する。

### プロファイル補正提案（自動適用禁止）
attack-groups.json の frequency 値について、実観測に基づく補正提案を以下の形式で出力する。
knowledge/ の自動書き換えは禁止。Issue/PR として提案し、人間レビュー後に手動で更新する。

```
補正提案 [グループ名]:
  T1566 frequency: 0.82 → 0.87（根拠: 直近30日の観測でX/Y件が本Techniqueを使用）
```

---

## 週次検証レポート（forecaster/verification/YYYY-MM-DD-verification.md）

pipeline-forecast-verification.md の「チャット表示形式」に準拠した内容を Markdown 形式で
`forecaster/verification/YYYY-MM-DD-verification.md`（YYYY-MM-DD は実行日）に保存する
（PR上での可読性優先）。以下を必ず含める:

- 予報別検証（確度・出口クラス E1〜E4・トラック fast_72h|slow_7d・判定・根拠1〜2行）
- 週次サマリー主指標（全予報統合・M2ガード1）
- 補助内訳（トラック別・主指標に昇格させない・slow_7d の期限超過自動外れ件数を含む）
- **キャリブレーション表（確度別的中率・目標帯乖離・Brierスコア）**:

  | 確度 | 総数 | 的中 | 部分的中 | 外れ | 検証不能 | 的中率（部分含む） | 目標帯 | 乖離判定 | Brierスコア |
  |------|------|------|----------|------|----------|--------------------|--------|----------|-------------|
  | 高 | | | | | | | 70%以上 | | |
  | 中 | | | | | | | 40〜70% | | |
  | 低 | | | | | | | 40%未満 | | |

- カバレッジ（M1ゲートの剪定可視化: 発行予報数 / 候補主題数・見送りクラス数）
- 発行ルール遵守チェック結果（違反ゼロの場合もその旨を明記）
- 確認されたバイアス・改善ポイント

---

## 実行手順

1. 入力を読み込む: `forecaster/forecasts/daily/YYYY-MM-DD.json`（サイドカーJSON・存在すれば
   一次入力・過去14日分）・`outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json`（過去14日分）・
   `forecaster/forecasts/daily/YYYY-MM-DD.md`（サイドカーJSON不在日のみ一次入力・それ以外は
   補足参照）・対応期間の observations・既存 verification ファイル（当月分・前月分）。
2. 検証対象の予報を列挙する: 検証窓が満了した未検証予報、および既存エントリのうち
   unverifiable（未確定）で窓が満了したもの。
3. CISA KEV JSON を直接取得し、E1 / E4 関連予報の `kev_snapshot` 差分を計算する（M4）。
4. 各予報を `hit_criteria` に従って判定する（M2トラック規則・期限超過自動miss・
   固定一次ソース＋エスカレーション規則を適用）。
5. 発行ルール遵守チェックを実施し、違反を `bias_analysis` に記録する。
6. `forecaster/verification/YYYY-MM.json` に結果を記録する（新規エントリは v1.1 新形式・
   未確定エントリは確定更新のみ・確定済み過去エントリは変更しない）。
7. `monthly_summary`（全体主指標＋ by_confidence キャリブレーション＋ by_track 補助内訳）を更新する。
   by_confidence では目標帯乖離判定（`calibration_status`）とBrierスコア（`brier_score`）を
   算出する（「確度キャリブレーション算出」参照）。
8. 前月の `verification/YYYY-MM.json` と比較し、同一確度の2ヶ月連続乖離を検出した場合、
   `bias_analysis` に確度較正見直し提案を起票する（発行済み予報の再採点は禁止）。
9. 対象 observations の `verified_outcome` と `related_forecast_id` を更新する（この2フィールドのみ）。
10. バイアス分析と補正提案を更新し、週次検証レポート
    `forecaster/verification/YYYY-MM-DD-verification.md` を作成する（キャリブレーション表に
    目標帯・乖離判定・Brierスコア列を含める）。
11. 変更した全ファイルをコミット対象として報告する。コミット・PR発行は週次検証スキル
    （`.skills/forecast-verification/SKILL.md`）の手順に従う（本手順書自体はコミットを行わない）。
