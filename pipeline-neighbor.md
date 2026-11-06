# pipeline-neighbor.md — Step 2c: 周辺諸国動向（Section 5）の収集・記録ルール

## 位置づけ

Section 5 は、わが国周辺諸国に関するサイバー関連の**活動・政策・組織・企業**の情報と、
それを理解するための**非サイバー情勢**（国家戦略・政治動向・国家心理・軍と組織の関係）を
記録する**報告専用の文脈層**である。

**予報の入力層ではない。** 観測（`forecaster/observations/`）・ベースライン・base_rate・
予報（`forecasts` / `tactical_forecast`）には一切入れない。理由は次のとおり。

- Section 5 は採用条件ではなく『関連性』で拾う。予報の観測母集団に混ぜると、
  ベースラインと base_rate が系統的に歪み、検証ループで予報ロジックの誤りと
  母集団の歪みを区別できなくなる（CLAUDE.md「網羅スイープ」節と同じ論理）
- 国への言及は事象の主体を意味しない。これを観測の帰属に流すと行動原則3に反する

既存の `geopolitical_signal` の経路（`pipeline-1b-apt.md`「地政学先行指標」・
`forecaster/prompts/01-normalize.md` R9）は**変更しない**。あの経路は技術的観測と対で
予報候補になる厳格な採用条件を持つ。Section 5 はそれと独立で、重複して記録してよいが、
Section 5 のエントリから観測を生成してはならない。

## 要件との対応

| 要件 | 本ステップでの扱い |
|---|---|
| 周辺諸国に関するサイバー攻撃関連活動 | category=`activity` |
| 周辺諸国のサイバー関連の政策 | category=`policy` |
| 周辺諸国のサイバー関連組織・軍と組織の関係 | category=`organization` |
| 周辺諸国のサイバーセキュリティ関連企業 | category=`company` |
| サイバーと非サイバー情報（国家戦略・政治動向・国家心理・軍と組織）の関連分析 | `non_cyber_linkage`（category=`geopolitical` は必須） |
| 引用する公開情報の妥当性の評価 | `source_assessment` |
| 日本語以外の言語で発信された情報 | `original_title` / `original_language`（原文を残し日本語で要約） |

## 対象国

`config.yml` の `neighbor_states`（primary / regional）が有効な国を決め、語彙は
`neighbor/states.json` が定義する。現在は primary = CN・RU・KP、regional = KR・TW。
国の追加・語の変更はその 2 ファイルを PR で変更する（このステップ内で書き換えない）。

## 入力

1. **Step 0.9 の走査結果** `neighbor-scan.json`（`scripts/neighbor_scan.py`）
   - 機械収集 raw（feeds.json の全フィード）を国別に走査した候補一覧
   - **ゲート対象**（関連度が `gate_min_relevance` 以上・調査窓内・重複除く）は、
     必ず『採用』または『理由付き除外』に割り当てる
   - `country_signal: actor_hint_only` の候補は国名の言及が無い。国との関係を主張しない
2. **Web 検索（補完のみ）**: 採用するエントリの非サイバー情勢（`non_cyber_linkage`）の事実を
   裏付ける場合に限る。検索結果は再現性が機械固定されないため、必ず URL を `references` に残し、
   該当エントリの `source_assessment.caveat` に『Web 検索で補完』と記す

## カテゴリ

| category | 採用する情報 | 例 |
|---|---|---|
| `activity` | 当該国の関与が語られるサイバー活動、または当該国が標的の活動 | 政府・ベンダーが国家との関係を明示した作戦 |
| `policy` | サイバー・情報通信・AI・暗号資産・データに関する法制・戦略・規制・制裁 | サイバー安全法の改正、輸出管理、起訴・懸賞金 |
| `organization` | サイバー関連の政府機関・軍部隊・組織再編、軍と組織の関係 | 新部隊の創設、機関の権限変更 |
| `company` | 当該国のセキュリティ関連企業の動向（買収・報告書・政府との関係） | ベンダーの調査報告、政府系企業の動き |
| `geopolitical` | 非サイバー情勢。**サイバーとの関連を示す形でのみ**記録する | ミサイル発射、首脳会談、選挙、軍事演習 |

`activity` のうち技術的詳細（IoC・TTP・マルウェア）を持つものは、Section 2 の APT エントリが
正である。Section 5 では技術的詳細を複製せず、`related_apt_campaign_ids` /
`related_cves` で参照し、国の文脈（誰が・どの政策の下で・どの組織が）だけを記す。

## 国との関係（country_basis）

| 値 | 意味 | attribution |
|---|---|---|
| `state_attributed_by_source` | 情報源が当該国の関与を明示している（category=activity のみ） | **必須** |
| `located_in_country` | 当該国に所在する組織・当該国の政策 | null |
| `target_country` | 当該国が標的 | null |
| `context_only` | 国との関係の主張なし（文脈情報） | null |

- **帰属判断は慎重に（行動原則3）**: `state_attributed_by_source` は、情報源が国家との関係を
  **明示**した場合だけ使う。TTP の類似・アクター名の一致・国名の言及だけで使わない
- 使う場合は `attribution` に `stated_by`（明示した情報源名）・`wording`（原文の言い回し・
  300 字以内の引用）・`confidence` を必ず書く。レポートが帰属を判断したのではなく、
  情報源の記述の引用であることがテキストにも明記される
- 複数の情報源で食い違う場合は、それぞれの記述を別の事実として記し、断定しない

## 事実と推測の分離（行動原則2）

- `facts[]`: 出典で確認できた事実だけを 1 文ずつ書き、`ref` で `references` の番号を指す。
  **事実に『（推測）』を混ぜない**
- `assessment`: 推測・評価は別欄に書く。本文は『（推測）』を含め、`confidence`
  （low / medium / high）を必ず付ける
- 分からないことは『わかりません』と書く。根拠のない補完をしない（行動原則1）
- 数値・日付・組織名は出典の記載をそのまま使う。丸めない・補わない

## 非サイバー情勢との関連（分析 c）

`non_cyber_linkage` は『事実』と『（推測）の評価』を対で持つ。

- `context_type`: `strategy`（国家戦略）/ `politics`（政治動向）/ `national_sentiment`
  （国家心理・世論）/ `military_org`（軍と組織の関係）
- `fact`: 非サイバー側の事実（出典番号付き）
- `assessment`: サイバー活動・政策との関連についての（推測）と確度
- 時期が重なっているだけでは因果を主張しない。『時期的な重なりがある』に留める
- `national_sentiment` は国営メディアの語り口に依存しやすい。**その国の政府が何を述べたか**
  として記録し、世論の実態とは書かない

## 出典の評価（分析 e）

各エントリに `source_assessment` を付ける。

| 項目 | 規則 |
|---|---|
| `primary_source` | 発信源自身の公表（政府の発表・ベンダー自身の報告書）なら true。転載・報道は false |
| `independent_sources` | 独立した情報源の数。**同一ベンダー系列・同一通信社の転載は 1 件**と数える |
| `state_affiliated` | 国営メディア等、政府系の情報源を参照するなら **true**（`references` に `state_media` があれば必須） |
| `caveat` | `state_affiliated` が true のときは必須。『当該国政府の主張であり事実の裏付けではない』旨を書く。Web 検索で補完した場合もここに書く |

`references[].source_class` は government / vendor / research / news / state_media / other。
国営メディアは**事実の裏付けに使わない**（その国が何を主張したかの記録にのみ使う）。
ベンダーは自国政府の影響下にあり得るため、帰属主張は『当該ベンダーがそう述べた』事実として扱う。

## 言語

- `original_title` と `original_language` に原題と言語（ISO 639-1）を残し、`title` と
  `facts` は日本語で要約する
- 参照 URL は**原文**を指す。翻訳ページの URL に置き換えない
- 機械翻訳に依存した解釈は `assessment` 側に（推測）として書き、事実欄に入れない

## 処理ゲート（dispositions）

Step 0.9 のゲート対象は、1 件ずつ `dispositions` に記録する。

```json
{ "candidate_id": "9db2bb1c771f0b75", "decision": "adopted", "entry_id": "nbr-2026-11-06-001" }
{ "candidate_id": "4a1c...", "decision": "excluded", "reason": "mentioned_only" }
```

除外理由: `no_neighbor_relation`（国との関係なし）/ `out_of_scope`（対象外）/
`duplicate_of_entry`（既存エントリと重複・`entry_id` 必須）/ `insufficient_evidence`（根拠不足）/
`marketing`（宣伝・広報）/ `mentioned_only`（言及のみ）。

「取りこぼし」と「意図的な不採用」は事後に区別できないため、無記録の除外は許されない。
検証器（`validate_neighbor_context.py --scan`）がゲート対象を再計算し、未処理が 1 件でも
あればコミットを止める。`neighbor_context.scan` の件数は走査結果をそのまま転記する
（推定値を書かない）。走査自体が失敗した場合は `scan.status: "failed"` を記録し、
その旨を日次サマリーに明記する。

## 禁止事項

- Section 5 のエントリから観測（observation）・予報・Technique・`actor_group` を生成する
- エントリに `techniques` / `ttps` / `actor_group` / `base_rate` 等の予報層の項目を持たせる
- 国名の言及・アクター名の一致・TTP の類似だけで国家帰属を記録する
- 事実欄への推測の混入、出典番号の無い事実
- 国営メディアの主張を事実として記録する
- `forecaster/knowledge/` の書き換え（行動原則5）

## 出力と検査

```bash
python3 scripts/neighbor_scan.py --date "${TODAY}" \
  --window-start "${WINDOW_START}" --window-end "${WINDOW_END}" \
  --output ".cache/daily-security-intel/${TODAY}/neighbor-scan.json"

# Step 3: security-report.json に neighbor_context を書いた後
python3 scripts/render_neighbor_section.py --date "${TODAY}" --append-to-full

# Step 4: コミット前
python3 scripts/validate_neighbor_context.py --date "${TODAY}" \
  --scan ".cache/daily-security-intel/${TODAY}/neighbor-scan.json" --require
```

スキーマは `pipeline-output-schema.md`「周辺諸国動向エントリ」を参照。テキストは JSON から
`render_neighbor_section.py` が決定論的に生成する（手で書き起こさない）。
