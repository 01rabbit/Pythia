# prompts/03-forecast.md — ステージ03: 予報生成

## あなたの役割

本日の observations・ベースライン・グループプロファイルを統合し、
定量的根拠に基づいたサイバー脅威予報を生成する。

このステージは既存パイプラインの `pipeline-3-weighting.md` の【攻撃予報（48〜72時間）】セクションを
**強化**するものであり、**置き換えではない**。
生成した予報は `forecaster/forecasts/daily/YYYY-MM-DD.md`（人間向け正本）と
`forecaster/forecasts/daily/YYYY-MM-DD.json`（機械可読正本・サイドカー）に**二重出力**する。
既存パイプラインの outputs/ へのコピーは行わない（pipeline-3-weighting.md 側から参照するのみ）。

---

## 入力

1. `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`（当日）
2. `forecaster/baseline/technique-freq.json`
3. `forecaster/baseline/group-activity.json`
4. `forecaster/knowledge/attack-groups.json`
4b. `forecaster/knowledge/group-aliases.json`（グループ名寄せマップ・Step B/C の照合に使用）
4c. `forecaster/knowledge/attack-group-history.json`（ATT&CK 由来のグループ過去事例・cited・
    Step C のレパートリー照合と Step C''' の一次出典付き過去事案参照に使用）
5. `forecaster/knowledge/technique-chains.json`
6. `forecaster/knowledge/poc-exploitation-criteria.json`（T3採用のPoC難易度足切り）
7. `forecaster/knowledge/incident-visibility-timelines.json`（M2 検証窓割当の根拠）
8. 当日レポート JSON の CVE エントリの `epss`（EPSS スコア/パーセンタイル）・`status.kev_registered`（M3 確度アンカー用）
9. `forecaster/knowledge/product-categories.json`（Step C'' 類似過去事例検索の CVE→製品カテゴリ抽象化辞書）
10. 検証済み過去予報ストア（Step C'' が `scripts/retrieve_similar_cases.py` 経由で読む）:
    `forecaster/verification/YYYY-MM.json`・`forecaster/forecasts/daily/*.json`・`forecaster/observations/`
11. `forecaster/knowledge/kev-leadtime-stats.json`（KEVリードタイム実測分布・
    E1 検証窓と base_rate_estimate の実測参考。`_limitations` 厳守。
    起点は NVD 公開日であり、起点=実悪用確認の実測は kev-initial-add-timelines.json が
    正（両者は補完関係・混用しない）。ファイルが存在しない場合は参照せずスキップする）
12. `forecaster/knowledge/epss-kev-calibration.json`（KEV追加**前日**の EPSS%ile 実測・
    M3 EPSS 条件の感度検証用。`_limitations` 厳守。運用上の登録後 EPSS 値の充足率とは
    別の量である点に注意。ファイルが存在しない場合は参照せずスキップする）

---

## 判定ロジック（4ステップ）

### Step A': KEV登録 + 実確認イベント起点

当日 observations に `exploitation_stage: "kev_listed"` または
`exploitation_stage: "active_exploitation"` を含む CVE があり、かつ以下のいずれか1つが
同日 observations または当日ニュースソースで実確認されている場合のみ予報候補とする。

- 対象製品の新規スキャン増加・悪用試行がCERT/SIEMレポートで確認されている
- 新規C2インフラ・IOC（IP / ドメイン / ハッシュ）が公開されている
- PoC公開後48時間以内の攻撃加速報告が確認されている

`KEV` 単体の場合は予報を生成しない。observation の `tags` に `kev_watch` を追記し、
翌日以降の観測を待つ。

ベースライン期間が14日未満でも、上記の実確認条件を満たす場合は予報候補として扱う。

KEV起点予報テンプレート:

- Evidence: `CISA KEV登録日: YYYY-MM-DD + 実確認の内容と出典`
- 的中判定条件: `対象製品への新規スキャン・侵害試行・悪用PoC公開のいずれか（72h以内）`
- 確度上限: `中`
- 注記: `（推測）KEV登録後の攻撃加速は過去パターン。個別環境での発生は確認されていない。` を必ず付与

### Step A: Technique 逸脱スコアの算出

当日 observations の各 Technique 出現件数をカウントし、baseline と比較する。

```
逸脱 σ = (当日件数 - mean_per_day) / stddev
```

| σ | 警戒レベル |
|---|-----------|
| σ < 1.0 | 平常 |
| 1.0 ≤ σ < 2.0 | 注意（caution） |
| σ ≥ 2.0 | 警戒（warning） |

baseline が未確立（stddev = 0 or null、または `baseline_status: "not_established"`）の
Technique は「ベースライン未確立」として別枠で報告する。
これらの Technique にσを算出して警戒レベル（注意・警戒）を付けることは禁止する
（sample_count が極小のエントリは新規1件でも +4σ 級になり誤検知源となるため）。
定性的言及（「本日初観測」「ベースライン未確立のため逸脱評価不能」等）のみ可。

**σ逸脱の予報文言ルール**: σ逸脱（1.0σ以上）を予報や分析の文言に反映する際は、報道量・観測件数を
実際の攻撃活動と直結させない。observations は報道・公開情報のプロキシであり、報告件数の増加が
必ずしも攻撃活動そのものの増加を意味しない（報道量バイアス）。このため σ逸脱を文中で言及する
場合は必ず以下の形式に従う。

```
〜の報告が増加（推測: 活動増加の可能性）
```

- 悪い例: 「Lazarus Groupの活動が急増している」（報道量増加を断定的な活動増加として記述）
- 良い例: 「Lazarus Group関連の報告が増加（推測: 活動増加の可能性）」
- σ逸脱を根拠に Tier 昇格・確度引き上げを行う場合も、根拠欄の文言は上記形式を用い、
  「報告件数の逸脱」と「実際の活動水準」を混同しない。

### Step B: グループ活性化の判定

`group-activity.json` の `sigma_deviation` を参照する。

**対象グループの判定は `group-aliases.json` による名寄せ後の canonical 単位、
および `parent_rollups` の parent_group 単位で行う**（例: Sapphire Sleet / Andariel /
TraderTraitor の観測は APT38 / Andariel / TraderTraitor の canonical 行に加え、
`parent_rollups` の Lazarus Group 行としても評価する）。
`attack-groups.json` との照合も、生の actor_group 文字列ではなく名寄せ後の
canonical / parent_group で行う。

| 条件 | 判定 |
|------|------|
| sigma_deviation ≥ 2.0 | 活性化（警戒） |
| 1.0 ≤ sigma_deviation < 2.0 | やや活性化（注意） |
| last_seen が7日以内かつ sigma_deviation 不明 | 直近観測あり（要注視） |

**`baseline_status: "not_established"` の行（canonical・parent_rollups とも）の
sigma_deviation を活性化判定に使うことは禁止する**（生涯1回の観測でも +1.4σ となり
誤って「活性化」判定されるため）。該当グループは「ベースライン未確立・直近観測あり」
として定性的言及のみ可とし、上表の「要注視」扱いを上限とする。
`sigma_note: "week_early_provisional"` が付いた σ も単独では活性化判定に使わず、
参考値として扱う。

### Step C: 次段階TTP予測

活性化グループについて `attack-groups.json` の `typical_tactics_order` を参照する。
対象グループの特定は名寄せ後の canonical / parent_group で行う。
`attack-groups.json` のキーと canonical が一致しない場合は `group-aliases.json` の
aliases / parent_group を経由して照合する（例: canonical "APT38" は
parent_group "Lazarus Group" のプロファイルを参照してよい。その場合は
アンブレラ帰属にもとづく推定であることを「（推測）」として明記する）。

1. 当日の observations でそのグループが観測された最後の tactic を特定する。
2. `technique-chains.json` の `transition_matrix` から次段階への遷移確率を参照する。
3. 遷移確率 ≥ 0.60 のものを予報候補とし、`attack-groups.json` の `common_techniques` から
   次段階の代表 Technique を推定する。

この推定は「（推測）」として必ず明記すること。

**レパートリー照合（attack-group-history.json・cited 出典付き）**: Step C で言及する次段階
Technique 候補は、`attack-group-history.json` の当該グループ（名寄せ後 canonical / parent_group）の
`techniques` に含まれるか必ず照合する。

- **含まれる場合**: 「（推測）」表記は維持したまま、根拠欄に ATT&CK 出典を併記してよい
  （例: `既知レパートリー内: G0032 T1190（MITRE ATT&CK v19.1, https://attack.mitre.org/groups/G0032）（cited）`。
  バージョンは同ファイルの `_attack_version` を記載する）。これは言及の質を高める定性的裏付けであり、
  **Tier 昇格・確度引き上げ・σ代替の根拠にはしない**（発動根拠は従来どおり
  Step A'/A/B/C' の観測事実のみ）。
- **含まれない場合**: 「既知レパートリー外（ATT&CK v[_attack_version] 時点）」と明記し、
  当該 Technique の言及を見送るか注意点1行へ格下げする。**照合は降格方向を優先する非対称運用**
  とする（Step C'' の類似事例検索と同じ思想）。
- `attack-group-history.json` のみに登録があり `attack-groups.json` に未登録のグループ
  （例: Turla / APT28 / Mustang Panda / Gamaredon Group / Velvet Ant 等）は
  `typical_tactics_order` を持たないため次段階「予測」は行わない。既知レパートリーの
  定性的言及（cited 出典付き・「（推測）」明記）のみ可とする。
- ★この照合は予報文の品質管理専用である。日次正規化（01-normalize.md R3/R4）で観測に
  Technique / 帰属を付与する根拠には使用禁止（既知TTPからの類推付与禁止は不変）。

**evidence_basis ゲート（placeholder値の使用禁止）**: `technique-chains.json` の遷移確率・
`attack-groups.json` の `frequency` には `evidence_basis`（区分は `_evidence_basis_legend` 参照:
`placeholder` = 出典のない初期推定値 / `observed` = observations 実データから較正済み /
`cited` = 外部一次情報に出典明示）が付与されている。**`evidence_basis.type` が `observed` の
値のみ** Step C の遷移確率判定・予報の直接根拠として使用してよい。`placeholder` および
`cited` は現時点では発動根拠に使用禁止とする（`cited` の**数値**をゲート対象から緩和する場合は
人間レビューを経てから行う）。

なお `attack-group-history.json`（ATT&CK 由来・cited 相当）は**頻度・遷移確率を含まない
「在/不在」のみの過去事例データ**であり、本ゲートの対象（数値の発動根拠化）には該当しない。
その許容用途は上記「レパートリー照合」（定性・降格方向優先）と Step C'''（一次出典付き
過去事案の参照）に限定する。`frequency` / `transition_matrix` の数値ゲートは
本ファイル導入後も**不変**である（レパートリー照合の導入は PR レビュー＝人間承認を経て有効化）。

- `attack-groups.json`: `common_techniques[].evidence_basis.type` を個別エントリごとに確認する。
- `technique-chains.json`: `transition_matrix` の遷移確率は個別付与ではなく、トップレベルの
  `matrix_evidence_basis`（`applies_to: "transition_matrix.*.next.*"`）による一括付与方式を採る。
  判定手順は次のとおり。
  1. まず `matrix_evidence_basis.exceptions` に該当する `from`/`to` の組み合わせがあるか確認する。
     あれば exceptions 側のエントリを優先して参照する。
  2. exceptions に該当がなければ `matrix_evidence_basis.type` を適用する。
  3. `exceptions` に載っていても `type` フィールド自体を持たない・明示的に `observed` と
     書かれていない限り、そのエントリも `matrix_evidence_basis.type`（現状 `placeholder`）を
     継承しているとみなす。exceptions は根拠の補足説明であり、区分の自動昇格ではない。
  現状（2026-07時点）は `matrix_evidence_basis.type: "placeholder"` のため、
  `transition_matrix` の遷移確率は原則すべて Step C の発動根拠として使用禁止である。
  該当する遷移は「（推測・未較正の初期値に基づく参考情報）」として定性的に言及するにとどめ、
  予報のTier昇格・確度根拠には使わない。
- 本ゲートの対象は `frequency`（attack-groups.json）と `transition_matrix` の遷移確率
  （technique-chains.json）の数値のみである。`low_visibility_chains[].evidence_basis`
  （文字列型・個別チェーンの出典メモ）は本ゲートの対象外であり、従来どおり M1/M2 の
  slow_7d 割当根拠として参照してよい。
- `_observed_preview` のように「calibration_status: 統計的に不十分」と明記された値も
  昇格されるまでは placeholder 扱いのまま参照してはならない。
- 判断に迷う場合は evidence_basis 側を疑い、予報を見送るか注意点1行へ格下げする
  （原則1: Evidence起点の義務化に従う）。
- 実務上、上記判定手順により当面 Step C は「遷移確率 ≥ 0.60」を予報の直接根拠にできない
  （すべて placeholder のため）。この場合 Step C は「（推測・未較正の初期値に基づく参考情報）」
  として言及するにとどめ、予報候補としては他ステップ（Step A'・Step A・Step B・Step C'）の
  観測事実に基づくものを優先する。observed への昇格後は本ゲートの運用を見直す。

### Step C': 認証情報・トークン連鎖予報

当日 observations に以下のいずれかが観測された場合は、認証情報・トークンの二次利用を
48〜72時間の予報候補として別枠評価してよい。

- `T1555`（Credentials from Password Stores）を含む observation
- `T1528`（Steal Application Access Token）を含む observation
- `T1539`（Steal Web Session Cookie）を含む observation
- 大規模認証情報漏えい・フィッシングキャンペーン検出の observation

連鎖予報テンプレート:

- Evidence: `流出 / 窃取イベントの observation_id`
- 予報内容: `窃取された認証情報・トークンが48〜72時間以内に再利用される可能性がある`
- 的中判定条件: `クレデンシャルスタッフィング攻撃増加・横展開・別組織での不正ログイン観測`
- 確度上限: `中`
- 注記: `（推測）認証情報の二次利用は過去事例に基づく経験則。パスワード変更後もセッショントークンが残存する場合あり。` を必ず付与
- 関連Technique: `T1078`（Valid Accounts）、`T1550`（Use Alternate Authentication Material）を参考として記録してよい
  ただし推測であり、根拠あるTechnique紐付けとしては記録しない

法執行・摘発に関する observation がある場合も、流出資産の継続利用予報は維持してよい。
C2摘発 observation には「摘発はリスク低下であって終息ではない」と注記する。

### Step C'': 類似過去事例の想起（内部実績・Case-Based Retrieval）

Step A'〜C' で確定した各予報候補について、**蓄積済みの検証済み過去予報から類似事例を検索し、
その実績（hit/miss/partial）を確度付け・ベースレート見積もりの根拠に反映する**。
設計の全体像・濫用防止ガードは `forecaster/case-based-retrieval-design.md` を正とする。

**この検索は LLM の記憶で行わない**。必ず決定論的スクリプトで引く（原則1: ハルシネーション厳禁）。

手順:

1. 各予報候補から検索キーを組み立てる（`outcome_channel` / `cve`（リスト）/ `actor_group`（生名可・
   スクリプトが名寄せ）/ `techniques`（親T-idリスト）/ `tactics` / `exploitation_stage` /
   `forecast_class` / `tier`）。
2. 次を実行する（発行日を `--date` に渡す。**発行日より前の事例のみ**が対象となり未来リークを防ぐ）:

   ```
   python3 scripts/retrieve_similar_cases.py --date YYYY-MM-DD \
     --candidate '{"outcome_channel":"E1","cve":["CVE-YYYY-NNNNN"],"actor_group":"...","techniques":["T1190"],"exploitation_stage":"kev_listed","forecast_class":"fast_72h","tier":"T1"}'
   ```

3. 出力の `aggregate`（`n_cases` / `n_hit` / `n_partial` / `n_miss` / `empirical_hit_rate` /
   `observed_gate_passed`）と `matched_cases`・`guidance` を読み、以下に反映する:
   - **Markdown「過去パターン」欄**: 検索結果の要約を記述する（従来の自由記述＝担当者の記憶頼りを置換）。
     必ず「（過去実績）」と明記し、**当該事案の予測を断定する根拠にしない**（原則2: 事実と推測の分離）。
     例: `過去パターン: 類似5件（outcome_channel=E2・actor=Lazarus系・製品=金融API）中 的中0・部分0・外れ5（経験的的中率0%）。（過去実績）`
   - **`base_rate_estimate`**: `observed_gate_passed=true`（＝`n_cases` が最小サンプル数以上）の場合のみ、
     `empirical_hit_rate` を**参考**に主観値を較正してよい。**自動上書きはしない**（少数サンプルの過信防止）。
   - **サイドカー JSON `retrieval`**: `aggregate` の該当フィールドをそのまま記録する（監査証跡）。

**濫用防止ガード（非交渉・design §6）**:

- **確度の引き上げには使わない（降格方向のみ）**。類似事例の高的中率を根拠に確度=高へ昇格させることを
  禁止する。逆に類似事例が全滅（`empirical_hit_rate=0.0`・`guidance` が★で警告）の型は、
  **確度降格・発行見送り・注意点1行への格下げの根拠にしてよい**（M3 の Automatable 降格と同じ非対称性）。
  これは教訓14（E2追随IOC 8/8=0%）のような系統的過信をデータ駆動で自動再発見する経路である。
- **hit_criteria を緩める根拠にしない**（過去に外れたからと的中条件を甘くしない・教訓12）。
- `observed_gate_passed=false`（サンプル不足）の集計は base_rate 較正に使わず「参考（サンプル不足）」表示に留める。
- スクリプトが返す `guidance` 文をそのまま判断の一次根拠とし、独自解釈で上書きしない。

### Step C''': 外部類似事案の参照（Phase D・インターネット上の過去事案）

Step C'' の**内部実績**に加えて、**インターネット上の類似過去事案**（CERT/ベンダー/CISA 等の
一次公開情報）を参照し、防御行動の具体化・先回り監視シグナルの補強に用いてよい。内部データが
浅い時期（ベースライン未確立期）を補う目的の**補助**ステップである。

**原則1（ハルシネーション厳禁）を最優先する**。以下のゲートを全て満たす事案のみ採用する:

1. **一次ソースに出典URLを明示できる**こと（CERT・PSIRT・ベンダー公式・CISA 等）。二次報道・要約
   ブログのみを根拠にしない。出典URLは `retrieval.external_cases[].source_url` に記録する。
2. 参照した事案は `retrieval.external_cases`（`source_name` / `source_url` / `published_date` /
   `relevance`）へ**監査証跡として記録**する。`relevance` には当該事案との類似点と示唆を書き、
   推測は「（推測）」と明記する。
3. **外部事案は base_rate_estimate の直接根拠にしない**（内部の検証済み実績＝Step C'' の集計とは
   別軸・較正されていない）。用途は「推奨アクション」「先回り監視」欄の具体化と、防御行動フレーミング
   （原則2）の補強に限る。
4. 外部事案を根拠に攻撃者帰属を新規に作らない（原則3）。TTP 類似のみで断定しない。

`attack-group-history.json` の `campaigns`（C番号・first_seen / last_seen・ATT&CK URL 付き）は
一次出典要件（ゲート1）を満たす**事前審査済みの過去事案**として参照してよい。参照時は
`external_cases` に `source_name: "MITRE ATT&CK Campaign C0022（Operation Dream Job）"` の形式で
出典URL（ATT&CK キャンペーンページ）とともに記録し、`relevance` に first_seen / last_seen と
当該予報との類似点を書く（推測は「（推測）」明記・ゲート2〜4 は通常どおり適用）。

ゼロデイ主題の予報では `knowledge/zeroday-itw-priors.json`（Google Project Zero 由来・
各エントリに CVE と advisory URL）も同様に事前審査済みの過去事案として参照してよい。
用途は Section 2 ゼロデイ特報の文脈付け・「先回り監視」の具体化に限り、`_limitations`
（検知バイアス・真の発生率ではない）を厳守する。**カテゴリ別の出現数を『このカテゴリで
ゼロデイが出る確率』として base_rate_estimate や確度の根拠にしない**。

外部事案が原則1のゲートを満たせない（一次出典を示せない）場合は、**参照しない**（記憶からの
それらしい事案の捏造を絶対にしない）。該当なしの場合 `retrieval.external_cases` は省略または空配列とする。

### Step D: 予報の絞り込みと Tier 判定

`pipeline-forecast-verification.md` のルール（M1〜M4 含む）に完全準拠する。

- 最大2件
- T1 > T2（σ≥1.0）> T2（KEV+実確認）> T3 の優先順
- 同Tier内ではKEV起点を優先
- T3 は原則「確度: 中」
- ベースライン逸脱の定量証拠があれば T2 への昇格根拠として使用可能。
  ただし **`baseline_status: "established"` のσに限る**。`baseline_status: "not_established"`
  のエントリのσ（および null のσ）を Tier 昇格・活性化判定の根拠に使うことは禁止し、
  「ベースライン未確立」として定性的言及のみ可とする

**M1 観測可能性ゲート（発行前必須）**: 各予報の的中条件を観測出口クラス E1〜E4（KEV初回追加 / 新規IOC公開 / CERT初回勧告 / PoC公開）の一次・二値イベントに紐付ける。「国内被害報道」「KEV再登録」「悪用拡大（曖昧）」を的にする予報は発行せず注意点1行へ格下げ。

**M3 EPSS+SSVC 確度アンカー**: 確度=高は「KEV登録 AND EPSS percentile≥0.95 AND SSVC=Act/Attend」を満たす場合のみ。SSVC `Automatable=no`（ASLR回避・認証・多段要）は確度=高から自動降格。EPSSは確度裏取りのみに使い72h的中条件に流用しない。EPSS 条件（%ile≥0.95）の**事前予見可能性（感度）**の実測は `epss-kev-calibration.json` を参照する。同ファイルは KEV 追加**前日**の値を測っており、M3 が運用上参照する登録後 EPSS 値（EPSS v3+ は KEV 収載を特徴量に含むため事後に押し上がる）の充足率とは別の量である。前日感度の低さを根拠に閾値を引き下げるのはカテゴリエラーであり禁止。新規公開直後の CVE の較正には `by_freshness_v4_era.fresh_lag_le_30d`（現行モデル v4 での測定×公開30日以内）を主参照とし、同層が `insufficient_sample` の場合は `by_freshness.fresh_lag_le_30d`（モデル版混合）と `by_model_era.v4` を併読して限界を明記する。参照キーが存在しない場合はファイル不在時と同様に参照せずスキップする。閾値の変更は `pipeline-forecast-verification.md` 定量ゲートDの改定手続き（ホールドアウト窓での見直し）に従い**人間レビュー経由でのみ**行い、予報生成時に独自判断で緩めない。

**確度: 低の扱い**: 確度「高」「中」の適用条件（A〜D）をいずれも満たさないが、M1 観測可能性ゲート（下記）の発行前チェックリストを通過する予報には確度「低」を適用してよい。「低」は発行を見送るべき曖昧な予報ではなく、精度は保証できないが防御行動として発行価値がある予報という積極的な分類である。適用条件・目標的中率帯の正式定義は `pipeline-forecast-verification.md` の「確度: 低」適用条件を参照する（本書では重複定義しない）。「低」を適用する場合も的中判定条件（hit_criteria）の記載義務は変わらない。

**M2 検証窓**: 外部報道依存の主題（漏洩→国内被害等）は `forecast_class: slow_7d` へ割り当て。72h的中率の分母に混入させない。割当判断は `incident-visibility-timelines.json` の median_days_to_external_report に従う（3日超は fast_72h で発行しない）。ベンダー追随IOCの的中条件への扱いは下記「E2追随IOC除外（全Tier）」に従う。

**slow_7d の検証期限（分類別・一律+7日固定にしない）**: `incident-visibility-timelines.json` は
credential_leak_to_attack_report（中央値14日）・domestic_incident_media_report（中央値10日）・
apt_geographic_spillover（中央値21日）など、外部可視化までの中央値が7日を上回る分類を既に記録して
いる。`deadline_date` はこの中央値に合わせて設定し、一律+7日に固定しない（2026-07-10 精度検証の
分析・Issue #45 対応）:

| `incident-visibility-timelines.json` の分類キー | 検証期限（発行日+N日） |
|---|---|
| credential_leak_to_attack_report | +14日 |
| domestic_incident_media_report | +10日 |
| apt_geographic_spillover | +21日 |
| 上記いずれにも該当しない slow_7d 主題 | +7日（フォールバック値） |

採用した分類キーと日数根拠は `forecast_class_rationale` に1行明記する。期限超過の未確定は
この分類別期限の到達をもって自動で「外れ」に倒す（M2ガード2・保留の永続化禁止は変わらない）。
発行後にこの期限を後から延長・短縮すること（トラック移動に準じる運用）は禁止する。

**T3足切り**: T3予報候補は `poc-exploitation-criteria.json` の required を全て満たし disqualifying を満たさない場合のみ採用。1つでも欠ければ本編・参考Aの注意点1行へ格下げ（教訓10）。

**low-visibility遷移**: `technique-chains.json` の `low_visibility_chains`（漏洩→BEC・BYOVD回避更新）に該当する主題は外部報道を的中条件にせず slow_7d または先回り監視へ。

**E2追随IOC除外（全Tier・累計6件連続外れへの対応）**: 「一次ソースの詳細分析公開後72時間以内に追随IOC（競合ベンダー・一次ソース自身のいずれを問わず新規の IP / ドメイン / ハッシュ / 侵害指標）が公開される」ことを的中条件とする `forecast_class: fast_72h` の E2 予報は、**T1〜T3 の全Tierで発行しない**。この前提は 2026-06〜2026-07 で6件連続外れ（Windchill CVE-2026-12569・APT28 PRISMEX・Chrome WebGL UAF・FortiBleed・Cisco UCM CVE-2026-20230・npm北朝鮮サプライチェーン）しており、構造的過信としてほぼ確定した。

対応（優先順）:
1. 的中条件を E1（KEV初回追加）へ置換できる場合は E1 で `fast_72h` 発行する。
2. 一次ソース自身による明示的な「**同一キャンペーン・同一CVE の続報 / 追加IOC更新**」に限定できる場合のみ E2 を残してよい。この場合、別キャンペーンの類似IOCを的中に構成させないため、**帰属・対象エコシステム・C2インフラの3点一致**を `hit_criteria` に明記する（教訓: PolinRider を npm北朝鮮キャンペーンの続報と誤認しかけた事例）。
3. 上記いずれも満たせない「追随IOC公開期待型」の主題は `forecast_class: slow_7d` へ割り当てるか、本編注意点1行へ格下げする。

この除外は 2026-07-07 に人間レビュー（01rabbit・PR #38）により **正式除外**として確定済み（実績8/8=0%）。当初 Issue #19 が定めた `pct_within_72h≥50%`／`sample_count≥10` の閾値ルールは撤回した（実データが8件で頭打ち＝到達不能かつ発行停止で蓄積経路が閉じたため）。根拠データと決定記録は `vendor-ioc-followup-timelines.json`（`summary_statistics.decision_log`）を参照。将来 `pct_within_72h` が反転する新規事例が観測された場合のみ、同ファイルへ追記のうえ人間レビューで再検討する。

**M4 KEVスナップショット**: 各予報に発行時点のKEV状態（dateAdded / ランサムフラグ / 参照セット）を `kev_snapshot` として記録し、検証時に再登録（変化なし）を非的中判別できるようにする。

**base_rate_estimate（発行時ベースレート見積もり・記入必須）**: 各予報に、その的中条件（hit_criteria）が
「予報のスキルなしに偶然成立する確率」の発行時主観値を 0〜1 で記録する（サイドカーJSONの
`base_rate_estimate`）。この値は予報の情報量（ベースレート対比でどれだけ優れた予報か）を後から
測定するための記録であり、的中判定基準を緩めたり厳しくしたりする用途には使わない。

記入指針:

- **E1（KEV初回追加）を的中条件とする予報**: 対象CVEが**既にKEV未登録**で、かつ実悪用・PoC公開等の
  強いEvidenceがある場合でも、CISAのKEV追加自体は候補となるCVE全体で見れば発生率が高くない
  事象であることに留意し、根拠なく低い値（例: 0.05未満）に倒さない。一方、KEV登録済みCVEの
  「再登録」を誤って的中条件にしないよう M4 の非的中判別を優先する（本フィールドとは別軸）。
  Evidenceが強い（実悪用試行が既に観測されている等）T1予報ほどベースレートは相対的に高くなる
  （0.2〜0.4程度を目安とし、個別の状況に応じて調整する）。実測参考として
  `kev-leadtime-stats.json` の `era_2023_plus_recommended.pct_within_3d`（KEV追加が
  確定した集合で NVD公開から lag≤3日＝fast_72h の+3日窓相当で追加された割合）と
  `fresh_subset_lag_le_90d` を参照してよい。ただし以下を厳守する:
  - 同ファイル `_limitations` 参照。この値は**方向未定の参考値**であり、0.2〜0.4 目安の
    代替アンカーにしない（生存バイアスは上振れ要因だが、時間原点の不一致〔起点=NVD公開
    であり予報発行=実悪用観測ではない〕と negative_lag 群〔ゼロデイ型・最速層〕の除外は
    下振れ要因で、方向が混在する）。ゼロデイ型の予報ではこの分布より速い。
  - Step C''（内部検証実績）が `observed_gate_passed=true` の較正値を出せる場合は
    **内部実績を優先**し、本統計は内部実績が無い型の参考に限る。
  - 「実悪用確認→KEV追加」の実測は `kev-initial-add-timelines.json`（起点が異なる
    補完ファイル）を参照する。
- **E2〜E4（新規IOC公開・CERT初回勧告・PoC公開）を的中条件とする予報**: 発行時点で既にPoC公開や
  ベンダー分析が進行中であればベースレートは相対的に高い（0.3〜0.5程度）。逆に新規性の低い
  観測（単発の脆弱性報告のみ）から発行する予報はベースレートを低め（0.1未満）に見積もる。
- **T3（新規PoC/KEV追加からの急拡大予測）**: 一般に武器化までの成功率は低いため、ベースレートは
  低め（0.1〜0.2程度）を基本とし、poc-exploitation-criteria.json の足切り条件を満たす場合のみ
  やや高めに調整してよい。
- 数値の厳密な較正は不要（主観値でよい）が、**同種の予報間で一貫した相対順序**（Evidenceが
  強いほど高いベースレート）を保つこと。極端な値（0または1に近い値）は根拠を明記しない限り
  避ける。
- この見積もりは検証ステージ（04-verify.md）が的中実績と突合し、ベースレート対比の予報スキルを
  月次で算出するために使う。予報生成段階では見積もり値の記録のみを行う。

---

## 出力ファイル形式（Markdown + サイドカー JSON の二重出力）

予報1回の生成につき、同一内容を2ファイルへ出力する。**Markdown が人間向け正本、
サイドカー JSON（`forecaster/schema/forecast.schema.json` 準拠）が検証・確度別集計・
期限管理の機械可読正本**である。両ファイルの内容（confidence・tier・hit_criteria 等）は
必ず一致させること（不一致は検証ステージでの誤判定の原因になる）。

### 生成手順

1. Step A'〜D の判定結果から確定した予報（最大2件）ごとに、Markdown 本文用の記述と
   サイドカー JSON 用のフィールド値を**同時に**組み立てる（後付けでJSON化しない。
   Markdown の文章表現とJSONの構造化値の間で数値・enum が食い違わないようにするため）。
2. `forecaster/forecasts/daily/YYYY-MM-DD.md` を下記 Markdown テンプレートで出力する。
3. `forecaster/forecasts/daily/YYYY-MM-DD.json` を下記 JSON テンプレートで出力する。
   `forecast_id` は `fc-YYYYMMDD-N`（N=当日連番・1始まり）とし、`forecast_index` は
   Markdown本文の「予報N」の N と一致させる。
4. 予報がゼロ件（Step A'〜D のいずれも予報候補なし）の日は、Markdown は通常どおり
   「予測」セクションに予報なしの旨を記載する。サイドカー JSON は `forecasts: []` の
   空配列 wrapper を出力する（ファイル自体は生成する）。
5. 出力後、`python3 scripts/validate_forecasts.py --date YYYY-MM-DD` でサイドカー JSON を
   検証する。違反があれば発行前に修正する（違反を残したままコミットしない）。

### Markdown テンプレート

`forecaster/forecasts/daily/YYYY-MM-DD.md` に以下の形式で保存する。

```
# サイバー脅威予報 YYYY-MM-DD

生成時刻: YYYY-MM-DD HH:MM JST

## 警戒レベル: [平常 / 注意 / 警戒]

## 事実（本日の観測サマリー）
観測件数: N件
Technique 逸脱上位:
  - T1566 (initial-access): +2.3σ [警戒] — 当日X件 / 平常平均Y.Y件/日
  - T1059 (execution): +1.2σ [注意]
活性化グループ:
  - Lazarus Group: 当週X件 / 週平常平均Y.Y件 (+Z.Zσ) [警戒]

## 分析
[ベースライン逸脱の解釈。事実として確認できたことのみ記述。σ逸脱の言及は「〜の報告が増加（推測: 活動増加の可能性）」形式を用いる。]

## 予測
[Tier・確度・根拠・推定部分を明記。推測には「（推測）」を付ける。]

・予報1: [タイトル]
forecast_id: fc-YYYYMMDD-1
Tier: X
確度: 高/中/低（M3: 確度=高はEPSS%ile≥0.95 AND KEV AND SSVC=Act/Attend。Automatable=noは自動降格。低はA〜Dいずれも非充足だがM1通過・pipeline-forecast-verification.md「確度: 低」適用条件を参照）
観測出口クラス: E1/E2/E3/E4（M1）
検証窓: fast_72h / slow_7d（M2・slow_7dは割当根拠1行）
検証期限: YYYY-MM-DD（fast_72hは+3日固定。slow_7dは上記M2の分類別表に従う分類キーごとの日数。該当分類なしの場合は+7日をフォールバックとする）
Evidence: [具体的なソース名と日付]
過去パターン: [Step C'' の類似過去事例検索の要約。「類似N件中 的中X・部分Y・外れZ（経験的的中率W%）」形式。必ず「（過去実績）」明記。該当なしは「類似過去事例なし」]（過去実績）
外部類似事案: [Step C''' で一次ソース出典を示せた外部事案があれば要約。防御行動・先回り監視の補強用。なければ省略]（推測を含む場合は明記）
確度アンカー: [EPSS percentile / KEV状態 / SSVC決定 / Automatable / EPSS算出日]（M3）
ベースレート見積もり: 0.XX（この的中条件が偶然成立する確率の発行時主観値。記入指針は上記参照）
推定部分: [推論箇所の明示]（推測）
先回り監視: [最初に現れるシグナル]
的中判定: [観測出口クラスE1〜E4の一次・二値イベントのみ。「国内被害報道」禁止（M1・原則B）]
除外条件: [的中とみなさない条件。例: 他機関リストへの追加・既存エントリ更新・再登録は非的中]
KEVスナップショット: [dateAdded / ランサムフラグ / 参照セット]（M4・E1予報時）

## 推奨アクション
[予測に対応する防御行動]

## ベースライン未確立の観測（参考）
[stddev=0 / baseline_status: "not_established" / baseline 未収録の Technique・グループ出現リスト。σ・警戒レベルは付けない]
```

### JSON テンプレート（サイドカー）

`forecaster/forecasts/daily/YYYY-MM-DD.json` に `forecaster/schema/forecast.schema.json` 準拠で
以下の形式で保存する。全フィールドの意味・enum は同スキーマの description を正とする。

```json
{
  "_schema_version": "1.0",
  "_forecast_date": "YYYY-MM-DD",
  "_source_markdown": "forecaster/forecasts/daily/YYYY-MM-DD.md",
  "forecasts": [
    {
      "forecast_id": "fc-YYYYMMDD-1",
      "forecast_index": 1,
      "subject": "[Markdown「予報1」のタイトルと同一内容の1行]",
      "tier": "T1",
      "confidence": "high",
      "forecast_class": "fast_72h",
      "forecast_class_rationale": "[slow_7d の場合は必須。fast_72hでも根拠が明確なら記載推奨]",
      "outcome_channel": "E1",
      "window": "fast_72h",
      "deadline_date": "YYYY-MM-DD",
      "hit_criteria": "[Markdownの「的中判定」と同一内容]",
      "exclusions": "[Markdownの「除外条件」と同一内容]",
      "base_rate_estimate": 0.0,
      "kev_snapshot": {
        "cve": "CVE-YYYY-NNNNN",
        "date_added": null,
        "ransomware_flag": null,
        "reference_set_hash": null
      },
      "evidence": "[Markdownの「Evidence」と同一内容]",
      "anchor": {
        "epss_percentile": 0.0,
        "epss_model_date": "YYYY-MM-DD",
        "kev_registered": false,
        "ssvc_decision": "Attend",
        "automatable": "yes"
      },
      "related_observation_ids": ["obs-YYYY-MMDD-NNN"],
      "related_group": null,
      "estimated_portion": "[Markdownの「推定部分」と同一内容。省略可の場合は省略]",
      "retrieval": {
        "n_cases": 0,
        "n_hit": 0,
        "n_partial": 0,
        "n_miss": 0,
        "empirical_hit_rate": null,
        "observed_gate_passed": false,
        "matched_forecast_ids": [],
        "external_cases": []
      },
      "verified_outcome": null
    }
  ]
}
```

`retrieval` は Step C'' のスクリプト出力 `aggregate` をそのまま記録する（監査証跡）。
Step C'' の検索を実施しなかった予報では `retrieval` を省略または `null` にしてよい。
`external_cases` は Step C''' で一次ソース出典を示せた外部事案のみ記録する（原則1）。

予報がゼロ件の日は `"forecasts": []` とする（`_forecast_date` / `_source_markdown` は記載してよい）。
`verified_outcome` は必ず `null` で出力する（CLAUDE.md 行動原則4・検証ステージ04-verify.mdのみが書き込む）。

---

## 重要制約

- 事実（observations）と推測（次段階予測）を絶対に混在させない。
- `attack-groups.json` に登録されていないグループの次段階予測は行わない
  （登録の有無は `group-aliases.json` による名寄せ後の canonical / parent_group で判定する。
  `attack-group-history.json` のみに登録があるグループは次段階予測の対象外のまま、
  既知レパートリーの定性的言及（cited 出典付き）のみ可とする）。
- `attack-group-history.json` は確度の引き上げ・Tier 昇格の根拠に使わない
  （レパートリー照合は降格方向優先・定性的裏付けのみ）。観測への Technique / 帰属付与の
  根拠にも使用禁止（01-normalize.md R3/R4 不変）。
- 地政学シグナル単体での予報生成は禁止する。
  `geopolitical_signal` を含む observation に加え、同日の独立した技術的観測
  （IOC公開 / 新規TTP報告 / CERT勧告のいずれか）が揃った場合のみ予報候補とする。
- ベースライン期間が14日未満の場合、定量逸脱スコアを予報の根拠として使わない。
  その場合は既存パイプライン（pipeline-forecast-verification.md）のルールのみで予報を作成する。
- `pipeline-forecast-verification.md` の「確度: 高」「確度: 中」「確度: 低」適用条件・絞り込みルール・的中判定条件の記載義務を必ず遵守する。
- Markdown とサイドカー JSON は同日・同内容で二重出力する。JSON が機械正本であるため、
  Markdown 本文の数値・enum 相当語（Tier・確度・観測出口クラス・検証窓等）と
  サイドカー JSON のフィールド値は必ず一致させる。
- サイドカー JSON は `forecaster/schema/forecast.schema.json` に準拠させ、出力後
  `python3 scripts/validate_forecasts.py --date YYYY-MM-DD` で検証してから確定する。
- `verified_outcome` は正規化・予報段階では書き込まない（null 固定）。検証ステージ
  （04-verify.md）のみが書き込む（CLAUDE.md 行動原則4）。
- `technique-chains.json`・`attack-groups.json` の `evidence_basis.type` が `observed` 以外
  （`placeholder` / `cited`）の値は Step C の予報の直接根拠に使用しない（上記 evidence_basis
  ゲート参照）。
- Step C'' の類似過去事例検索は**確度の引き上げに使わない（降格方向のみ）**。`observed_gate_passed=false`
  の集計は base_rate_estimate の較正に使わず参考表示に留める。過去に外れた型だからと hit_criteria を
  緩めない（design §6・教訓12）。検索は `scripts/retrieve_similar_cases.py` で決定論的に行い、
  LLM の記憶で類似事例を捏造しない（原則1）。
- Step C''' の外部事案は**一次ソースの出典URLを示せる場合のみ**参照し `retrieval.external_cases` に
  記録する。base_rate_estimate の直接根拠にはせず、推奨アクション・先回り監視の補強に限る。一次出典を
  示せない事案は参照しない（記憶からの捏造禁止・原則1）。
