# 類似過去事例検索（Case-Based Retrieval）— 予報エンジン拡張 設計書

ステータス: **提案（実装前レビュー待ち）**
起票: 2026-07-10
対象ブランチ: `claude/attack-forecast-past-cases-67iz0k`
関連原則: CLAUDE.md 行動原則 1（ハルシネーション厳禁）・2（事実と推測の分離）・5（knowledge 自動書き換え禁止）
関連ステージ: `forecaster/prompts/03-forecast.md`（Step C 拡張）・`forecaster/prompts/04-verify.md`（実績還流）

---

## 1. 背景と問題設定

### 提案の骨子
攻撃予報を立てる際、**当該事案（今日のCVE・攻撃者グループ・TTP集合）に類似する過去事例を蓄積データから検索し、
その過去事例が実際にどう転んだか（的中/外れ）を根拠として次の予測に反映する**。

### 現状：何をやっていて、何をやっていないか

| 区分 | 現状 | 種別 |
|------|------|------|
| Step C（次段階TTP予測） | `technique-chains.json` 遷移確率＋`attack-groups.json` 典型戦術順を参照 | **集計統計**（かつ現在 evidence_basis ゲートで発動禁止＝placeholder） |
| M2 検証窓割当 | `incident-visibility-timelines.json` の中央値 | **集計統計** |
| M4 KEV判定 | `kev-initial-add-timelines.json` | **集計統計** |
| 「過去パターン」欄（Markdown テンプレ） | 記入欄はある | **担当者の記憶・手動判断**（系統的検索なし） |
| **類似過去事例の個別想起** | **なし** | **未実装** ← 本設計の対象 |

**結論**: 集計値（平均・中央値・確率）の参照はあるが、「今日の事案に似た**具体的な過去事例を検索して引き当て、
その実績（verified_outcome）を根拠にする**」case-based retrieval は存在しない。「過去パターン」欄は
LLM/担当者の記憶に依存しており、蓄積データ（`observations/` `forecasts/daily/` `verification/`）への
決定論的アクセスがない。

### なぜ集計統計だけでは不足か
- 集計値は「母集団平均」であり、目の前の事案の固有条件（製品カテゴリ・actor・悪用ステージ・
  outcome_channel の組合せ）に条件付けられていない。
- Step C が placeholder ゲートで止まっている今、「過去に実際にこうなった」という observed 根拠が
  予報に一切効いていない。verified_outcome を持つ過去予報は、この穴を**実観測で**埋められる最良の材料。
- 原則1（Evidence起点）・原則2（事実と推測の分離）と整合的：集計確率より「この具体的過去事例で
  実際にこう転んだ」の方が反証可能で強い根拠になる。

---

## 2. 設計目標と非目標

### 目標
1. 予報候補ごとに、蓄積済みの類似過去**予報**とその**検証実績（hit/miss/partial）**を決定論的に検索する。
2. 検索結果を `base_rate_estimate`（発行時ベースレート）と Markdown「過去パターン」欄の**根拠**として供給する。
3. LLM の記憶ではなくスクリプトで引く（再現性・監査可能性・ハルシネーション遮断）。
4. 既存の evidence_basis ゲート思想と同じく「**observed 実績のみ根拠採用**」を貫く。

### 非目標（このフェーズではやらない）
- 予報の確度を検索結果で**自動的に引き上げる**こと（降格方向のみ・M3 と同じ思想。§6 参照）。
- `knowledge/*.json` の自動書き換え（原則5）。補正提案は Issue/PR で人間レビュー。
- 意味ベクトル・埋め込み検索の導入（初期は決定論的な構造化キー一致で足りる。§9 将来拡張）。
- 検証ステージ（04）の判定基準変更。本設計は**入口（母集団への情報供給）**のみに触れ、
  **出口（採点尺度・hit_criteria）には一切触れない**（M1〜M4 と同じ「入口可・出口固定」構造）。

---

## 3. データソース（すべて既存・Git 蓄積済み）

| ソース | パス | 提供するもの | 検索キーになるフィールド |
|--------|------|--------------|--------------------------|
| 観測 | `observations/YYYY/MM/YYYY-MM-DD.json` | 正規化済み観測（1情報=1obj） | `actor_group` / `actor_aliases` / `techniques[].technique_id` / `techniques[].tactic` / `target.sectors` / `target.geos` / `cve[]` / `exploitation_stage` / `geopolitical_signal` / `tags` |
| 予報 | `forecasts/daily/YYYY-MM-DD.json`（サイドカー） | 過去に発行した予報 | `outcome_channel` / `tier` / `confidence` / `related_group` / `kev_snapshot.cve` / `anchor.epss_percentile` / `base_rate_estimate` |
| 検証 | `verification/YYYY-MM.json` | **予報→実績の紐付け（一次価値）** | `entries[].outcome`（hit/miss/partial）/ `forecast_index` / `outcome_channel` / `tier` / `confidence` / `related_observation_ids` |

**一次価値は `verification/YYYY-MM.json`**：ここだけが「過去予報が実際にどう転んだか」を持つ。
`forecasts/daily/*.json` の `verified_outcome` にも同値が還流されうるが、月次検証JSONが正本。
観測ファイルの `verified_outcome` は補助。

---

## 4. 検索キーと類似度スコアリング

### 4.1 現在の予報候補からのキー抽出
Step A'〜D で確定した各予報候補（発行前）から以下を抽出する:

```
key = {
  outcome_channel:  E1|E2|E3|E4          # 最重要（的中構造が同じか）
  cve_products:     製品カテゴリ集合       # CVE→製品カテゴリ辞書で正規化（例: VPNアプライアンス, ブラウザ）
  actor_canonical:  group-aliases.json で名寄せした canonical / parent_group
  techniques:       {technique_id} 集合    # 親テクニックのみ
  tactics:          {tactic} 集合
  exploitation_stage: active/kev/poc/...
  forecast_class:   fast_72h | slow_7d
  tier:             T1|T2|T3
}
```

### 4.2 類似度スコア（重み付き・0〜1）
過去の各予報エントリ（`verification/*.json` の entry、related_observation で観測へ join）に対し:

| 要素 | 一致定義 | 重み（初期・要較正） |
|------|----------|----------------------|
| outcome_channel 一致 | 完全一致 | 0.30 |
| actor_canonical 一致 | 名寄せ後 canonical または parent_group 一致 | 0.20 |
| CVE 製品カテゴリ一致 | カテゴリ集合の Jaccard | 0.20 |
| techniques 集合 | technique_id 集合の Jaccard | 0.15 |
| tactics 集合 | tactic 集合の Jaccard | 0.05 |
| exploitation_stage 一致 | 完全一致 | 0.05 |
| forecast_class 一致 | 完全一致 | 0.05 |

`similarity = Σ(weight × 要素スコア)`。閾値 `similarity ≥ 0.50` を「類似事例」とし、
上位 N（既定 5）件を採用。**重みは暫定値。§8 の較正ルールに従い、現バイアス定義セットで
過学習しないこと**（M3 の EPSS 閾値と同じ注意）。

### 4.3 CVE→製品カテゴリ辞書
CVE番号そのものの一致は稀（同一CVEの再来はほぼない）。製品カテゴリで抽象化して初めて
「似た事案」になる。新規 knowledge ファイル `knowledge/product-categories.json` を追加し、
`cve_or_product → category` を人手でマッピング（自動推論しない・原則1）。初期は観測に既出の
製品のみ収録し、未収録CVEはカテゴリ空（＝この要素スコア0）で扱う。

---

## 5. 検索結果の集計と予報への反映

### 5.1 集計出力（スクリプトが返す構造）
```json
{
  "forecast_candidate_ref": "fc-20260710-1 (発行前の内部ID)",
  "matched_cases": [
    {
      "forecast_id": "fc-20260624-1",
      "forecast_date": "2026-06-24",
      "similarity": 0.72,
      "outcome": "miss",
      "outcome_channel": "E2",
      "matched_on": ["outcome_channel", "actor_canonical", "techniques"],
      "verification_evidence": "検証JSONのevidence_for_outcome抜粋"
    }
  ],
  "aggregate": {
    "n_cases": 5,
    "n_hit": 1, "n_partial": 1, "n_miss": 3,
    "empirical_hit_rate": 0.40,           // (hit + partial) / n_cases
    "hit_rate_strict": 0.20,              // hit / n_cases
    "observed_gate_passed": true          // n_cases ≥ 最小サンプル数(既定3)を満たすか
  }
}
```

### 5.2 予報フィールドへの反映（03-forecast.md）
- **Markdown「過去パターン」欄**: 従来の自由記述を、検索結果の要約に置換。
  例: `過去パターン: 類似5件（outcome_channel=E2・actor=Lazarus系・製品=金融API）中、的中1・部分1・外れ3（実績的中率40%）。うちFortiBleed 6/24予報は外れ。`
  **必ず「（過去実績）」と明記し、当該事案の予測断定に使わない**（原則2）。
- **`base_rate_estimate`**: 現在は主観値。類似事例が最小サンプル数（既定3件）以上ある場合、
  スクリプトの `empirical_hit_rate` を**参考提示**し、担当者/LLM が主観値を較正する。
  **自動上書きはしない**（少数サンプルの過信を防ぐ。§6 のガード）。
- **サイドカー JSON**: 新フィールド `retrieval` を追加（§7）。監査証跡として matched_cases の
  forecast_id とスコアを記録。

### 5.3 04-verify.md への還流（軽微）
検証時、類似事例の実績集計が予報の `base_rate_estimate` と乖離していれば
`bias_analysis` に記録（例:「E2追随IOC型は経験的的中率0%だが base_rate 0.3 で発行された」）。
これは既存の教訓14（E2追随IOC全滅）を**データ駆動で自動再発見**する経路になる。

---

## 6. 濫用防止ガード（尺度ロンダリング禁止・非交渉）

M1〜M4 と同じ「入口のみ操作可・出口固定」を厳守する。

1. **確度の引き上げに使わない（降格方向のみ）**。類似事例の高的中率を根拠に確度=高へ昇格させることを
   禁止。逆に類似事例が連続外れ（例: 経験的的中率0%）の主題は、確度降格・発行見送り・注意点格下げの
   根拠に**してよい**。M3 の SSVC `Automatable` 降格ルールと同じ非対称性。
2. **hit_criteria を緩める根拠にしない**。過去に外れたからといって的中条件を甘くしない（教訓12）。
3. **最小サンプル数ゲート**（既定3件）。これ未満は `observed_gate_passed=false` とし、
   `base_rate_estimate` の較正には使わず「参考（サンプル不足）」表示に留める（M2 較正の
   「1ヶ月のみの乖離は記録に留める」と同思想）。
4. **verified_outcome を持つ事例のみ集計対象**。未検証（null）・検証不能の過去予報は
   分母に入れない（evidence_basis の observed 限定と同じゲート）。
5. **重みの過学習禁止**。スコア重み・閾値は現バイアス定義セット（2026-06 の13件等）で
   較正しない。ベースライン確立後にホールドアウト窓で見直す（§8）。
6. **knowledge 自動書き換え禁止**（原則5）。`product-categories.json` の拡充や重み変更は
   Issue/PR で人間レビュー。スクリプトは読むだけ。

---

## 7. スキーマ変更（サイドカー JSON）

`forecaster/schema/forecast.schema.json` の forecast オブジェクトに任意フィールド `retrieval` を追加:

```json
"retrieval": {
  "type": ["object", "null"],
  "description": "類似過去事例検索の結果サマリー（scripts/retrieve_similar_cases.py が生成）。監査証跡。予報の直接根拠にできるのは observed_gate_passed=true の集計のみ。",
  "properties": {
    "n_cases": { "type": "integer" },
    "n_hit": { "type": "integer" },
    "n_partial": { "type": "integer" },
    "n_miss": { "type": "integer" },
    "empirical_hit_rate": { "type": ["number", "null"] },
    "observed_gate_passed": { "type": "boolean" },
    "matched_forecast_ids": { "type": "array", "items": { "type": "string" } }
  }
}
```

`verified_outcome` と同様、予報発行段階でスクリプト出力を記録するのみ。検証ステージは触らない。
既存予報 JSON は `retrieval` を持たなくてもよい（任意・後方互換）。

---

## 8. 較正運用（過学習防止）

- スコア重み（§4.2）と閾値（similarity≥0.50・最小サンプル3）は**暫定値**。
- **現在のバイアスを定義した検証セットで較正してはならない**（M3 の EPSS 閾値と同じ戒め）。
- ベースライン（90日分）確立後、ホールドアウト窓（較正に使っていない期間）で
  「retrieval を使った予報」と「使わない予報」の的中率・Brierスコアを比較して見直す。
- 見直しは将来発行予報の**入口条件のみ**に及び、発行済み予報の再採点には及ばない（原則D）。

---

## 9. 実装スコープ（レビュー承認後）

| # | 成果物 | 内容 |
|---|--------|------|
| 1 | `scripts/retrieve_similar_cases.py` | §3 ソース走査・§4 スコアリング・§5.1 集計出力。`--date YYYY-MM-DD --candidate <キーJSON>` で起動。読み取り専用。 |
| 2 | `knowledge/product-categories.json` | CVE/製品→カテゴリ辞書（初期は観測既出分のみ・人手） |
| 3 | `forecaster/prompts/03-forecast.md` | Step C の後に「Step C''：類似過去事例の想起」を追加。§4〜§6 の手順とガードを明記。「過去パターン」欄の記入をスクリプト出力ベースに変更。 |
| 4 | `forecaster/schema/forecast.schema.json` | §7 の `retrieval` フィールド追加 |
| 5 | `forecaster/prompts/04-verify.md` | §5.3 の乖離記録（軽微追記） |
| 6 | `scripts/validate_forecasts.py` | `retrieval` を任意フィールドとして許容（既存検証を壊さない） |

### 段階導入
- **Phase A（最小）**: #1 スクリプト＋#3 プロンプト追記のみ。retrieval は「過去パターン」欄への
  参考情報供給に限定（JSON スキーマは変えず、Markdown 記述だけ強化）。低リスクで効果検証。
- **Phase B**: #2 辞書・#4 スキーマ・#6 バリデータで機械可読化・監査証跡化。
- **Phase C**: #5 で検証ループへ還流し、教訓の自動再発見（§5.3）を稼働。

Phase A のみでも「過去パターン欄が担当者の記憶頼り」という現状の穴は閉じられる。
Phase B/C は監査性と検証ループ統合のための拡張。

---

## 10. 原則との整合チェック

| 原則 | 本設計での担保 |
|------|----------------|
| 1 ハルシネーション厳禁 | 検索は決定論的スクリプト。LLM の記憶に「過去事例」を捏造させない。CVE→カテゴリは人手辞書。 |
| 2 事実と推測の分離 | 「過去パターン」欄は実績（事実）。当該事案の予測（推測）と混ぜず「（過去実績）」明記。 |
| 3 帰属は慎重に | actor 名寄せは既存 `group-aliases.json` に依拠。TTP 類似だけで新規帰属を作らない。 |
| 4 verified_outcome は04のみ | 本設計は verified_outcome を**読む**だけ。書き込まない。 |
| 5 knowledge 自動書換禁止 | スクリプトは読み取り専用。辞書・重み変更は人間レビュー。 |
| 6 全変更コミット | retrieval 出力はサイドカー JSON に記録され Git 履歴に残る。 |
| 出口固定（M1〜M4思想） | 入口（母集団への根拠供給）のみ操作。hit_criteria・採点尺度は不変。降格方向のみ。 |

---

## 11. レビュー論点（承認判断のための確認事項）

1. **段階導入の起点**: Phase A（Markdown 強化のみ）から始めるか、Phase B（スキーマ変更込み）まで一括か。
2. **CVE→製品カテゴリ辞書**: 手動収録の初期範囲（観測既出のみ / 主要製品を先行投入）。
3. **スコア重み・閾値**: §4.2 の初期値で妥当か。特に outcome_channel 0.30・actor 0.20 の配分。
4. **最小サンプル数**: 3件で妥当か（データ蓄積量が現状2週間強のため、当面 retrieval が発火しない
   可能性がある。閾値を下げて「参考」表示だけ出すか）。
5. **base_rate_estimate への反映度**: 参考提示に留めるか（本設計の推奨）、`observed_gate_passed=true`
   時は自動較正まで踏み込むか。
</content>
</invoke>
