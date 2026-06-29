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

形式: observation オブジェクトの JSON 配列 `[]`。

---

## 技術付与スコープ設定（phase1-config.json `normalization` 参照）

現在のモード: **`source_explicit_all`**（2026-06-28 にユーザー判断で `focus_group_only` から拡大）

- **全観測（CVE / APT / AI）に対し、情報源が明示する場合のみ** techniques・actor_group を付与する（通常ルール R3・R4 を全観測に適用）。
- `focus_group: "Lazarus Group"` は引き続き日次の重点【人間レビュー】対象（Technique 付与の正誤チェック先）だが、技術付与の対象を Lazarus に限定しない。
- ★R3・R4 の evidence-based 原則は厳守する。情報源が技術・帰属を明示していない場合は `techniques: []` / `actor_group: null` とし、推測による付与は引き続き禁止。
- ATT&CK 以外の体系（ATLAS 等）の技術は `techniques`（ATT&CK 専用）に入れない。該当する ATT&CK 技術が情報源から導ける場合のみ付与する（例: 盗用コンピュート悪用 → T1496 Resource Hijacking）。

---

## 正規化ルール（厳守）

### R1: 1情報 = 1オブジェクト
CVE・APT活動・AI攻撃のそれぞれを独立した observation オブジェクトに変換する。

### R2: observation_id の採番
形式 `obs-YYYY-MMDD-NNN`（例: `obs-2026-0626-001`）。
当日内で001から連番。既存ファイルがある場合は最大番号に続ける。

### R3: techniques フィールドの付与ルール
- ATT&CK Technique ID は確証がある場合のみ付与する。
- 情報源が特定の技術・手法を明記している場合のみ対応する ID を記載する。
- 確証がない・判断できない場合は `techniques: []` とし、`confidence: "low"` とする。
- `evidence` フィールドには「情報源が〇〇を記述していたため T1566 を付与」の形式で1文記載する。
- 推測・類推による Technique 付与は禁止。

### R4: actor_group の帰属ルール
- 情報源（CERT・セキュリティベンダー・政府機関）が明示している場合のみ記入する。
- TTPの類似だけで攻撃者グループを断定しない。不明な場合は `null`。

### R5: confidence の判定基準
| 値 | 条件 |
|----|------|
| high | CERT/政府機関の勧告 / 複数独立ベンダーの確認あり |
| medium | 信頼性の高い単一ベンダー報告 / OSINT複数確認あり |
| low | 単一ニュースソースのみ / Technique 付与不能 |

### R6: verified_outcome は必ず null
検証ステージ（04-verify.md）のみが書き込む。正規化ステージで変更禁止。

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
3. 全オブジェクトを配列にまとめ `forecaster/observations/YYYY/MM/YYYY-MM-DD.json` に書き出す。
4. ディレクトリが存在しない場合は作成する。
5. 処理件数（生成 observation 数）をチャットに報告する。

---

## 品質チェック（出力前に確認）

- [ ] `techniques` に ATT&CK 以外の ID（ATLAS 等）が含まれていないか
- [ ] 各 technique に情報源由来の `evidence`（1文）が付いているか（推測付与でないか）
- [ ] `actor_group` に情報源が明示していないグループ名が入っていないか
- [ ] `verified_outcome` がすべて `null` になっているか
- [ ] `confidence: "low"` のエントリで `techniques` が空配列になっているか
- [ ] CVE observation に `exploitation_stage` が付与されているか
- [ ] `observation_id` が重複していないか
