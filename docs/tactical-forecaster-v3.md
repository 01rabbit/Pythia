# Pythia Tactical Forecaster v3

Pythiaは脆弱性ニュースの要約器ではなく、観測済み事実から次に観測される戦術展開を
前向きに予報し、防御側の判断を早める「サイバー戦術予報士」である。

## 契約

1. Evidenceは取得時刻とhashを持ち、cutoffより後の情報を状態へ混ぜない。
2. ObservationはEventへ正規化し、同一CVE・同日・同状態の再報道を一つのepisode entryへ統合する。
3. 状態と予報候補は有限状態・許可遷移からコードで生成し、LLMに確率を書かせない。
4. 参照率は `current_state × target_event × next_state × horizon` ごとに測る。
5. 予報台帳は発行時にhashで凍結し、matching ruleを窓の途中で変えない。
6. bounded open worldでの未確認はmissではなく`not_observed`とする。
   ただし**`not_observed` が大半を占める状態を正常として通してはならない**。
   `check_verification_health.py` が「窓満了済みなのに hit も miss も0件」
   「not_observed が resolved の大半」を検出して落とす。
   偽陰性を避ける契約が、そのまま不可反証性に化けるのを防ぐためである。
7. 精度だけでなくBrier、log loss、AUC、coverage、棄権率、lead timeを家族別に評価する。
8. 現在はshadow modeであり、公開予報は0件。昇格はmodel registryの人間承認を要する。

人間承認だけでも昇格できない。`promotion-gates.json` の前向き標本数、陽性数、
Brier skill、AUC下限、較正、Evidence被覆率、時間整合性をfamily×horizon別に満たした
promotion summaryが必要である。summaryは `build_promotion_summary.py` が候補台帳と
固定時刻の検証結果から再生成し、CIはコミット済みの値との一致も検査する。違反時はCIが拒否する。
現行の `tf1-reference-only-v1` は参照クラス確率だけの較正用shadowモデルであり、AUCを
主張しない。弁別モデルを登録するまで `public_forecast_eligible=false` として公開昇格を禁止する。

## 確認チャネル

hit の受理判定は `source.type` ではなく、`source_channels.resolve()` が
**掲載元ホスト**（または構造化された `source.primary_reference.url`）から解決する
**確認チャネル**で行う。`source.name` に一次組織名が書かれていても昇格しない
（`「CISA / BleepingComputer」`の実際の掲載ホストは `www.bleepingcomputer.com` である）。`source.type` は媒体種別ではなく記事内容で付与されており、
同一媒体でも値が割れるため受理条件に使えない
（実測: 「The Hacker News」= news 79 / vendor_report 3 / advisory 4）。

チャネルは `cert` / `vendor` / `telemetry_provider` / `aggregator_news` の4種で、
定義は `forecaster/knowledge/source-channels.json` に置く（行動原則5により
自動書き換え禁止・追加はPRと人間レビュー）。登録簿にない組織は `unattributed` とし
hit にしない。`aggregator_news` と `unattributed` で不発になった件数は
検証出力の `blocked_by_channel` に必ず記録し、沈黙させない。集約ニュース掲載でも
記事が一次公表の原典URLを明示している場合は `source.primary_reference` に構造化して
残せば受理できる。ただし**受理には Evidence Ledger の取得証跡（`evidence_id`）が必須**で、
証跡の `source_url` が `url` と一致しなければ昇格しない（URL fragment は除く）。許可ホストのURLを
書くだけで hit を作れないようにするためである。証跡の無いものは
`primary_reference_unverified`、原典URL自体が無いものは
`aggregator_news_citing_primary` として区別する。

原典URLの取得証跡は、将来の自動collectorが作る。手動のURL取得入口は設けず、証跡が
無い集約ニュース記事は `primary_reference_unverified` として残し、hit にはしない。

候補が宣言する `verification_sources` は採点宇宙の `sources` から単一生成する。
二重管理すると宣言と hit 判定が食い違う。

被覆記録は Evidence Ledger から導出し（`record_source_coverage.py --from-evidence`）、
`derived_from` に evidence_id を残す。被覆記録が1件も無い間はモデル昇格を拒否する。

## 現在の予報対象

TF-1は脆弱性の `DISCLOSED → POC_PUBLIC → LIMITED_EXPLOITATION →
ACTIVE_EXPLOITATION → POST_EXPLOIT_ACTIVITY` を扱う。状態は明示された
`exploitation_stage` だけから導く。ATT&CKの侵入後tacticは状態を上書きせず、
`post_exploit_evidence` として戦況説明・追加収集の証拠に残す。`BROAD_CAMPAIGN`は現行データで
構造的に観測できないため、0件を低確率へ変換せず棄権する。

Actor・標的・インフラ・影響への展開予報はEvent/Case/Episodeを蓄積した後に、別family、
別matching rule、別評価母集団として追加する。TF-1の数字を流用しない。

## 日次順序

`snapshot → collect/normalize → event store → state(cutoff) → reference rates →
candidate freeze(issued) → integrity/transition validation → portfolio → report`

予報後は同じsource universeを監視し、窓満了時に決定論的に検証する。
