# forecaster/ — サイバー戦術予報士システム

既存の security-intel-routine に統合された予報精度向上サブシステム。

## 設計思想

1. 構造化が先、量は後 — 収集量ではなく正規化スキーマと検証ループが精度を決める
2. 予報と実績の突き合わせを必ず回す — 検証なき予報は精度向上しない
3. Git が記憶装置 — 全観測・予報・検証はコミット履歴として蓄積される

## ディレクトリ構成

```
forecaster/
  schema/
    observation.schema.json     # 正規化スキーマ定義
  knowledge/
    attack-groups.json          # ATT&CK Groups プロファイル（参照用）
    technique-chains.json       # Tactic 遷移確率
  observations/
    YYYY/MM/YYYY-MM-DD.json     # 正規化済み観測データ（日次蓄積）
  baseline/
    technique-freq.json         # TTP 出現頻度の平常分布
    group-activity.json         # グループ活性度の平常分布
  forecasts/
    daily/YYYY-MM-DD.md         # 日次予報
    weekly/YYYY-Www.md          # 週次サマリー
  verification/
    YYYY-MM.json                # 予報 ID × 実績の突合記録
  prompts/
    01-normalize.md             # ステージ01: 正規化指示
    02-baseline.md              # ステージ02: ベースライン更新指示
    03-forecast.md              # ステージ03: 予報生成指示
    04-verify.md                # ステージ04: 検証指示
```

## 4ステージパイプライン

```
[既存 collect] → [01 正規化] → [02 ベースライン更新] → [03 予報生成] → [04 検証]
                      ↑                                                       │
                      └─────────── verified_outcome 還流 ────────────────────┘
```

| ステージ | 実行タイミング | 出力 |
|----------|--------------|------|
| 01 正規化 | 日次（Step 3 完了後） | observations/YYYY/MM/YYYY-MM-DD.json |
| 02 ベースライン更新 | 日次（01 完了後） | baseline/*.json |
| 03 予報生成 | 日次（02 完了後） | forecasts/daily/YYYY-MM-DD.md |
| 04 検証 | 週2回（火・木 12:00 JST） | verification/YYYY-MM.json |

## 過去事象のバックフィル（machine_backfill）

日次ルーチン開始（2026-06-15）より前の実悪用確認イベントは
`scripts/backfill_observations.py` で CISA KEV の `dateAdded`（日付スタンプ付き一次記録）から
observations/ へ遡及取り込みできる。

- **対象は観測（observations/）のみ**。予報・検証の遡及生成は結果を知った上で書く
  後知恵バイアスとなり検証ループを汚染するため行わない
- 生成ファイルは `_normalization_mode: "machine_backfill_kev"` でマーキングされ、
  ベースライン統計（`scripts/regen_baseline.py`）からは**除外**される
  （日次収集と観測密度が異なるため、混ぜると σ 逸脱スコアが歪む）
- 用途: 過去事象の掌握・類似過去事例検索（`scripts/retrieve_similar_cases.py`）の母集団拡充
- Technique / actor_group の推測付与はしない（`techniques: []` 固定・人間レビューなしでの付与禁止）
- `reported-*.md` / `outputs/` には触れない（レポートしていないものを既報扱いにしない）

### APT の過去事例学習（knowledge 経路）

APT 活動は KEV のような日付付きイベント列を持たないため、観測バックフィルではなく
**知識ベースへの蒸留**で過去事例を取り込む。

- `scripts/build_attack_group_history.py` が MITRE ATT&CK の Groups / Campaigns から
  `group-aliases.json` 記載の追跡対象グループの既知 TTP・過去キャンペーン
  （first_seen / last_seen 付き）を抽出し、
  `knowledge/attack-group-history.json` に出典付き（cited 相当）で書き出す
- knowledge/ の自動書き換え禁止ルールに従い、再生成は日次ルーチンからは行わず
  **必ず PR 提案 + 人間レビュー**を経る
- 用途は予報生成時の事前知識・過去事例の掌握。**日次正規化（01-normalize.md R3/R4）で
  観測に Technique / 帰属を付与する根拠には使用禁止**（既知 TTP からの類推付与は禁止のまま）
- 手書きキュレーションの `attack-groups.json` / `group-aliases.json` には触れない
- 予報ロジックへの接続（03-forecast.md）: Step C の**レパートリー照合**（次段階 Technique 候補が
  当該グループの ATT&CK 既知レパートリーに含まれるかを照合。含まれれば cited 出典を併記、
  含まれなければ格下げ＝降格方向優先の非対称運用）と、Step C''' の**一次出典付き過去事案**
  （campaigns の C番号・first_seen/last_seen・ATT&CK URL）として参照される。
  頻度・遷移確率の数値ゲート（placeholder 使用禁止）は不変で、
  Tier 昇格・確度引き上げの根拠には使わない

## Phase ロードマップ

- **Phase 0（Week 1）**: ディレクトリ・スキーマ確定 ✓ 完了（2026-06-26）
- **Phase 1（Week 2-8）**: Lazarus Group に絞り手動レビュー付きで正規化を2週間検証 → 検証ループ稼働 ← **現在ここ**
- **Phase 2（Week 8-16）**: 業界別脅威動向セクション追加
- **Phase 3（Week 16-24）**: D3FEND 防御連携・推奨防御アクション自動付与
- **Phase 4（Week 24+）**: データ匿名化・精度統計の外部発表

## Phase 1 完了条件

的中率の高さは問わない。以下が満たされていること:

- 収集情報の 80% 以上に TTP 付与（正規化カバレッジ）
- 90日分の平常分布が算出済み（ベースライン確立）
- 週次で的中率が記録されている（検証ループ稼働）

## 運用ルール（全ステージ共通）

1. ハルシネーション厳禁 — ATT&CK Technique の紐付けは確証ある場合のみ
2. 事実と推測の分離 — 予報文では観測（事実）と予測（推測）を区別し「（推測）」を明記
3. actor 帰属は慎重に — 情報源が明示する場合のみ。TTP類似だけで断定しない
4. verified_outcome を勝手に埋めない — 検証ステージ（04）のみが書き込む
5. プロファイル補正は自動適用しない — 必ず人間レビューを挟む
6. 全変更はコミットする — 観測・予報・検証は Git 履歴として残す
