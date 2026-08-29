# prompts/01-normalize.md — ステージ01: 正規化

## あなたの役割

あなたはサイバー脅威アナリストである。
既存パイプライン（pipeline-1-cve.md / pipeline-1b-apt.md / pipeline-ai-1.md）が収集した生情報を受け取り、
`forecaster/schema/observation.schema.json` に従って構造化された観測データに変換する。

---

## 入力

当日の日次レポート JSON（`outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json`）の以下フィールドを処理対象とする:

- `main_cve` — 本編CVE
- `reference_a` — 参考A CVE
- `reference_b` — 参考B CVE
- `zero_day_special` — ゼロデイ特報
- `apt_main` — APT活動本編
- `apt_notable` — APT活動注目動向
- `ai_attacks_main` — AI攻撃本編

---

## 出力先

`forecaster/observations/YYYY/MM/YYYY-MM-DD.json`

形式: **wrapper 形式に一本化する（スキーマ v1.2）**。素の JSON 配列 `[]` や独自形式での出力は禁止。

```json
{
  "_schema_version": "1.2",
  "_observation_date": "YYYY-MM-DD",
  "_normalization_mode": "source_explicit_all",
  "_normalization_note": "（任意の注記）",
  "observations": [
    { /* observation オブジェクト */ }
  ]
}
```

- `_schema_version` と `observations` は必須。`_schema_version` は `"1.2"` 固定。
- 正規化直後に `scripts/stamp_observation_availability.py` を実行し、推測ではなく
  実時計測の `available_at_utc` とEvidence Ledger参照を各observationへ付ける。
- `_observation_date` はファイル名の日付と一致させる。
- observation オブジェクトの構造は `forecaster/schema/observation.schema.json` の `$defs/observation` に従う。
- 書き出し後は `python3 scripts/validate_observations.py --date YYYY-MM-DD` で検証し、違反ゼロを確認してからコミットする。

---

## 技術付与スコープ設定（phase1-config.json `normalization` 参照）

現在のモード: **`source_explicit_all`**（2026-06-28 にユーザー判断で `focus_group_only` から拡大）

- **全観測（CVE / APT / AI）に対し、情報源が明示する場合のみ** techniques・actor_group を付与する（通常ルール R3・R4 を全観測に適用）。
- `focus_group: "Lazarus Group"` は引き続き日次の重点【人間レビュー】対象（Technique 付与の正誤チェック先）だが、技術付与の対象を Lazarus に限定しない。
- ★R3・R4 の evidence-based 原則は厳守する。情報源が技術・帰属を明示していない場合は `techniques: []` / `actor_group: null` とし、推測による付与は引き続き禁止。「明示」の操作的定義（具体的な手口・挙動の記述があれば付与する）は R3 を参照。
- ATT&CK 以外の体系（ATLAS 等）の技術は `techniques`（ATT&CK 専用）に入れない。該当する ATT&CK 技術が情報源から導ける場合のみ付与する（例: 盗用コンピュート悪用 → T1496 Resource Hijacking）。

### R6: 一次公表の原典を構造化して残す（source.primary_reference）

報道記事は一次組織の報告を中継していることが多い（例: BleepingComputer が CISA の
勧告を伝える）。検証で「宣言した確認チャネルで確認できたか」を判定する根拠は
**掲載元ホスト**であり、`source.name` に一次組織名を書いても昇格しない。

- 実測: `「CISA / BleepingComputer」`の URL ホストは `www.bleepingcomputer.com` であり
  `cisa.gov` ではない。名前の言及で受理すると二次報道が確認事実になってしまう。
- 集約ニュース掲載の記事でも、**記事が一次公表の原典URLを明示している**場合は
  `source.primary_reference` に
  `{organization, url, evidence_id, citation_basis, published_at_utc?}` を入れる。
- **`evidence_id` は必須**である。原典を Evidence Ledger へ取得（スナップショット）して
  その `evidence_id` を書く。証跡の `source_url` が `url` と一致しない場合（URL fragment
  は除く）、
  および証跡が存在しない場合は昇格しない（`primary_reference_unverified`）。
  **許可ホストのURLを書くだけでは hit を作れない。**
- `citation_basis` には「記事中のどの記述が原典を指しているか」を書く。
- **本文からの推測で埋めてはならない**（原則1）。原典URLが記事に無い、または
  原典を取得できない場合は `primary_reference` ごと省略する。
  省略時は掲載元ホストで判定され、集約ニュースなら hit にならない（fail-closed）。

## 正規化ルール（厳守）

### R1: 1情報 = 1オブジェクト
CVE・APT活動・AI攻撃のそれぞれを独立した observation オブジェクトに変換する。

### R2: observation_id の採番
形式 `obs-YYYY-MMDD-NNN`（例: `obs-2026-0626-001`）。
当日内で001から連番。既存ファイルがある場合は最大番号に続ける。

### R3: techniques フィールドの付与ルール

**「明示」の定義（操作化）:**
情報源が **具体的な手口・挙動** を記述していれば、対応する ATT&CK Technique への機械的マッピングは「明示」とみなして **付与する**。
情報源本文に ATT&CK ID そのものが記載されている必要はない。
「ATT&CK ID の記載がない」ことだけを理由に `techniques: []` としてはならない。
一方、**グループ名のみ・「高度な攻撃」等の抽象記述** からの付与は禁止する。

**付与すべき例（具体的な手口・挙動の記述あり → 機械的マッピング可）:**

| 情報源の記述 | 付与する Technique |
|----|----|
| 「公開APIの未認証パストラバーサル脆弱性が実悪用された」 | T1190（initial-access） |
| 「Webシェルを設置して持続的なアクセスを確保した」 | T1505 / sub_technique_id: T1505.003（persistence） |
| 「フィッシングメールの添付ZIPを開かせてマルウェアを実行させた」 | T1566 / sub_technique_id: T1566.001（initial-access） |

**付与してはならない例（抽象記述・帰属のみ → 付与禁止）:**

| 情報源の記述 | 判断 |
|----|----|
| 「Lazarus Group によるものと帰属された」（手口の記述なし） | グループの既知TTPからの類推付与は禁止。`techniques: []` |
| 「高度で多段階な（sophisticated）攻撃キャンペーンが確認された」 | 抽象記述のみ。`techniques: []` |
| 「データ侵害が発生し個人情報が窃取された」（侵入経路の記述なし） | 結果のみで手口不明。T1190 等を推測付与しない。`techniques: []` |

**運用ルール:**
- `technique_id` は親テクニックID（`^T\d{4}$`。例: T1566）のみを記載する。サブテクニックは `technique_id` に直書きせず、別フィールド `sub_technique_id`（例: T1566.001）に記載する。`sub_technique_id` は `technique_id` と前方一致すること。
- `evidence` フィールドには「情報源が〇〇を記述していたため T1566 を付与」の形式で1文記載する。
- 手口の記述はあるがどの Technique に対応するか判断に迷った場合は、付与を見送り、observation の `techniques_note` フィールドに迷った理由を1〜2文で記録する。`techniques_note` 付きエントリは人間レビュー対象となる。
- 手口・挙動の記述が一切なく Technique 付与不能な場合は `techniques: []` とし、`confidence` の判定は R5 に従う。
- 推測・類推による Technique 付与は禁止。

### R4: actor_group の帰属ルール
- 情報源（CERT・セキュリティベンダー・政府機関）が明示している場合のみ記入する。
- TTPの類似だけで攻撃者グループを断定しない。不明な場合は `null`。

### R5: confidence の判定基準
| 値 | 条件 |
|----|------|
| high | CERT/政府機関の勧告 / 複数独立ベンダーの確認あり |
| medium | 信頼性の高い単一ベンダー報告 / OSINT複数確認あり |
| low | 単一ニュースソースのみ等、情報源の信頼度が低い |

`confidence` は **情報源の確度** を表し、Technique 付与の可否とは独立に判定する
（例: 政府機関の勧告で手口の記述がない場合、`techniques: []` かつ `confidence: "high"` があり得る）。

### R6: verified_outcome / related_forecast_id の書き込み権限
- `verified_outcome` は正規化段階では必ず `null`。**検証ステージ（04-verify.md）のみ** が書き込む。正規化・予報段階で変更禁止。
- `related_forecast_id` は正規化段階では `null` とする。**予報ステージ（03-forecast.md）が設定してよい**（観測を既存予報に紐付ける場合）。検証ステージも設定・更新できる。

### R7: summary の記述
- 1〜2文で記述する。
- 確認済みの事実のみ書く。推測・予測は含めない。
- CVEの場合: 「[製品名] の [脆弱性種別] 脆弱性 [CVE番号] が実悪用確認された。CVSS [スコア]。」
- APTの場合: 「[グループ名] が [標的セクター/地域] を対象に [手口の概要] を行ったことが確認された。」

### R8: exploitation_stage の付与ルール
CVE observation には `exploitation_stage` を必ず付与する。優先順は
`active_exploitation > kev_listed > poc_public > limited_exploitation > none > unknown`。
複数に該当する場合は最上位のみ採用する。

| 値 | 付与条件 |
|----|---------|
| active_exploitation | 複数の信頼できるソースで実悪用確認。KEV登録済みでも独立確認があればこれを優先 |
| kev_listed | CISA KEV登録済みで、独立した実悪用確認が取れていない |
| poc_public | PoC・exploitコードが公開済みで、実悪用は未確認 |
| limited_exploitation | 特定組織・地域限定の悪用報告 |
| none | 上記に該当しない理論的脆弱性のみ |
| unknown | 判断不能。情報源が不明確でハルシネーション回避が必要 |

APT活動・AI攻撃 observation では `exploitation_stage` を省略してよい。

### R9: geopolitical_signal の付与ルール
APT活動 observation で地政学シグナルを記録する場合のみ `geopolitical_signal` を付与する。

- `north_korea_nexus`: 北朝鮮ITワーカー詐欺、暗号資産窃取、Lazarus系部隊への連鎖が本文で確認できる
- `russia_nexus` / `china_nexus` / `iran_nexus`: 情報源が当該国家系の連鎖を具体的に示す
- `geopolitical_unattributed`: 連鎖はあるが国家帰属は明示されていない
- 根拠が弱い純軍事ニュースや政治ニュースのみでは付与しない

### R10: iocs の defang ルール
IoC を `iocs` に記録する場合:

- ドメイン・URLは defang 形式（`[.]` など）を推奨する
- defang形式に変換した場合は `defanged: true` を設定する
- 単純ブロック非推奨・VPN/プロキシ終端の可能性などがある場合は `note` に理由を記録する

---

## 実行手順

1. 入力 JSON の各エントリを読み込む。
2. 各エントリに対して上記ルールに従い observation オブジェクトを生成する。
3. 全オブジェクトを wrapper 形式（`_schema_version: "1.1"` + `observations` 配列）に一旦まとめ `forecaster/observations/YYYY/MM/YYYY-MM-DD.json` に書き出す。
4. ディレクトリが存在しない場合は作成する。
5. `python3 scripts/stamp_observation_availability.py --date YYYY-MM-DD` でv1.2へ固定する。
6. `python3 scripts/validate_observations.py --date YYYY-MM-DD` を実行し、違反があれば修正して再実行する（違反ゼロになるまでコミットしない）。
7. 処理件数（生成 observation 数）とバリデータ結果をチャットに報告する。

---

## 品質チェック（出力前に確認）

- [ ] 最終出力が wrapper 形式（`_schema_version: "1.2"` + `observations` 配列）になっているか（素の配列は禁止）
- [ ] `techniques` に ATT&CK 以外の ID（ATLAS 等）が含まれていないか
- [ ] `technique_id` にサブテクニックID（T1566.001 等）を直書きしていないか（サブテクニックは `sub_technique_id` へ、`technique_id` と前方一致）
- [ ] 各 technique に情報源由来の `evidence`（1文）が付いているか（推測付与でないか）
- [ ] 情報源が具体的な手口・挙動を記述しているのに、ATT&CK ID の記載がないことを理由に `techniques: []` としていないか（R3「明示」の定義を再確認）
- [ ] Technique 付与の判断に迷ったエントリに `techniques_note`（理由1〜2文）を記録したか
- [ ] `actor_group` に情報源が明示していないグループ名が入っていないか
- [ ] `verified_outcome` がすべて `null`、`related_forecast_id` がすべて `null` になっているか（正規化段階では埋めない）
- [ ] Technique 付与不能で `techniques: []` としたエントリの `confidence` が R5 の基準に従っているか
- [ ] CVE observation に `exploitation_stage` が付与されているか
- [ ] `observation_id` が重複していないか
- [ ] `python3 scripts/validate_observations.py --date YYYY-MM-DD` が違反ゼロで通ったか
