# pipeline-1-cve.md — Step 1: CVE調査ルール

## 調査区分

Step 1 のCVE調査は以下の2トラックで行う。
監視対象の製品リストは存在せず、製品リストによる絞り込みは行わない。
各CVE・脆弱性事象の帰属先は下記「トラックA/B 排他的決定木」で一意に決定する。
**トラック定義の正は本ファイルのみ**であり、SKILL.md・pipeline-soc-recommend.md 等は
本ファイルを参照する（二重定義しない）。

**トラック A（製品別CVE）**: 採用条件 A〜H を満たし、影響製品・OSSが特定できるCVEを収集し、
  Section 3【製品別CVE】として出力する。製品カテゴリは問わない。

**トラック B（トレンドCVE）**: Section 3 の個別エントリとして扱えない高インパクト事象
  （CVE未採番のゼロデイ、製品単位に紐付かないキャンペーン等）を収集し、
  `section_route: trends` タグを付けて Section 2【ゼロデイ・セキュリティトレンド】へ渡す
  （pipeline-2-trends.md が吸収する）。

---

## トラックA/B 排他的決定木

各CVE・脆弱性事象に対して上から順に判定し、**最初に該当した節で帰属先を一意に確定する**。
同一CVEを Section 2 と Section 3 の両方に個別エントリとして掲載することは禁止する
（Section 2 のAPT・トレンド記事の本文中でCVEに言及するのは帰属ではないため可）。

**D1. 期間内に採用条件 A〜H が1つも確認できない**
→ 不採用。既報（reported-cves.md 掲載済み）かつ変化なしは除外、
それ以外は下記「除外ルール」の低優先度フラグ規則に従う。

**D2. CVE採番済み かつ 影響製品・OSSが特定できる（ベンダーアドバイザリ・パッチ情報に紐付く）**
→ **トラック A（Section 3）へ帰属**。高インパクト条件（下記）の該当有無を問わず
Section 3 への帰属を優先する（Section 3 本編優先の原則）。
高インパクト条件に該当する場合は `high_impact: true` を付与し、
Step 3 の重みづけで Section 3 のゼロデイ特報・本編へ優先配置する。

**D3. D2に該当せず、高インパクト条件のいずれかに該当**
（CVE未採番のゼロデイ、単一製品に紐付かないキャンペーン・大規模スキャン・
エコシステム横断事象 等）
→ **トラック B（Section 2）へ帰属**。`section_route: trends` タグを付けて
pipeline-2-trends.md へ引き渡す。後日CVEが採番され製品に紐付いた場合は、
翌日以降の実行で D2 により Section 3 へ帰属し直す（reported-cves.md の備考に移行を記録する）。

**D4. 上記いずれにも該当しない**
→ Section 4（SOC推奨情報）の候補としてストックする
（採用判定は pipeline-soc-recommend.md の採用条件 α〜η による）。

### 高インパクト条件（D2のフラグ・D3の判定に使用）

- CISA KEV 新規追加
- CVSS 9.0以上 Critical
- ゼロデイ・実悪用確認
- PoC公開後 48h 以内の攻撃加速報告

※ 旧ルールにあった「国内で広く使われる製品」はトラック振り分け条件から除外した。
国内影響は Step 3 の軸2（実環境影響度）と参考A昇格トリガー（pipeline-2-trends.md）で評価する。

---

## CVE収集方針

製品を事前リストで絞り込まず、下記の採用条件 A〜H に基づいて満遍なく収集する。
優先度タグ（必須 / 高 / 中 / 低）は採用後に付与する。

### トラック A の採用ルール
- 期間内（調査窓 24h）に A〜H のいずれかが確認できれば対象製品を問わず採用
- CVE番号が付与されていなくても、ベンダーアドバイザリ（セキュリティアップデートへの言及）が
  期間内に更新された場合は「ベンダーアドバイザリ更新」として収集する
- 既報（reported-cves.md 掲載済み）かつ期間内に変化なし → 除外（ただし一覧に記録）

### トラック B のルール
- 帰属判定は上記「トラックA/B 排他的決定木」の D3 のみで行う（本節で独自の条件を追加しない）
- 該当事象には `section_route: trends` タグを付けて pipeline-2-trends.md へ引き渡す

---

## 調査ソース（優先順）
1. CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
2. NVD: https://nvd.nist.gov/
3. CVE Program（一次レコード）: https://www.cve.org/
   - NVD の分析・スコアリング完了前のレコード確認に使用する（新規採番直後のCVEはNVDに反映が遅れる場合がある）。
4. GitHub Advisory Database: https://github.com/advisories
5. OSV（OSS脆弱性DB）: https://osv.dev/
   - OSS はエコシステム・パッケージ・バージョン・コミット単位で照合できるため、
     ライブラリ・依存関係系CVEの影響バージョン特定に優先使用する。API・機械可読データあり。
6. JVN / JVN iPedia（国内製品・国内ベンダー照合）: https://jvn.jp/ / https://jvndb.jvn.jp/
   - 国内製品・国内ベンダーに関わるCVEは JVN iPedia で日本語情報・国内アドバイザリの有無を照合する。
   - プログラム照会には MyJVN API（https://jvndb.jvn.jp/apis/myjvn/index.html）を使用できる。
   - JVN iPedia 新着は security-intel-collector/feeds.json で機械収集済み（data/raw/ を一次入力とする）。
7. ベンダーアドバイザリ（Fortinet / Palo Alto / Ivanti / Microsoft / Cisco / Oracle 等）
8. BleepingComputer / The Hacker News / SecurityWeek
9. PoC情報: GitHub / Exploit-DB / Packet Storm / watchTowr / ProjectDiscovery
10. EPSS（Exploit Prediction Scoring System・FIRST.org）: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX
   - 各CVEの「今後30日以内に実悪用が観測される確率」スコア（0〜1）とパーセンタイル（全CVE中の相対順位）を返す較正済みモデル。
   - ★注意: EPSSは【30日窓・グローバル指標】であり、PYTHIAの予報窓（72時間）・国内スコープとは時間軸・地理軸が異なる。
     用途は【確度（高/中）の裏取りアンカー】に限定し、予報の的中判定条件（72h）には絶対に流用しない（M3・pipeline-forecast-verification.md 参照）。
   - スコアは日次更新されるため、予報発行時に取得した `model_date`（EPSS算出日）を記録し再現性を確保する。

## 採用条件 A〜H（期間内に1つ以上確認できること）
| 記号 | 条件 |
|------|------|
| A | CVE新規公開 |
| B | NVD新規登録・重要更新 |
| C | ベンダーアドバイザリ新規公開・重要更新 |
| D | CISA KEV新規追加 |
| E | ゼロデイ・実悪用の新規報道 |
| F | PoC・Exploitコードの新規公開 |
| G | GitHub Advisory新規公開・重要更新 |
| H | 侵害報告・攻撃観測・悪用キャンペーンの新規報道 |

## 除外ルール（フラグ付け・足切り禁止）
- 期間内に A〜H が確認できない古いCVEは除外
- 既報（reported-cves.md 掲載済み）かつ期間内に変化なし → 除外
- 採用済みCVEについては製品・種別を問わず足切り禁止
- 以下は除外ではなく `低優先度` フラグを付けて次ステップへ渡す:
  - CVSS 7.0未満 かつ KEV非登録 かつ PoC非公開
  - DoSのみ CVSS 8.0未満
  - 情報漏洩のみ CVSS 8.0未満

## 各CVEに付与するメタデータ
- CVE ID / 製品名 / CVSS（NVDを正とする）
- 採用契機: 新規公開 or 状況変化
- 期間内の変化: いつ・どのソースで・何が変化したか
- actively_exploited: true / false
- exploitation_stage: 以下の4値のみ使用可（enum・これ以外の表記は禁止）
  - `active_exploitation` — 実悪用が確認されている（KEV登録の有無を問わず、報道・ベンダー確認・ハニーポット観測等の根拠あり）
  - `kev_listed` — CISA KEV 登録済みだが、独立した実悪用観測の報道は未確認
  - `poc_public` — PoC・エクスプロイトコードが公開済みだが、実悪用・KEV登録は未確認
  - `none` — 上記いずれにも該当しない（悪用・PoCとも未確認。`no_exploitation_confirmed` 等の別表記は禁止し `none` を使用する）
  - 複数該当時は active_exploitation > kev_listed > poc_public > none の優先順で最上位1値のみを採用する
  - reported-cves.md の exploitation_stage 列にもこの語彙のみを記録する（`scripts/check_reported.py` が機械検査する）
- PoC公開: true / false / 未確認（true の場合URL必須）
- EPSS: score（0〜1）/ percentile（0〜1）/ model_date（EPSS算出日 YYYY-MM-DD）。取得不能な場合は null。
- 優先度タグ: 必須 / 高 / 中 / 低優先度
- 関連URL（全件保持）
- 監視SPL候補: 対象製品が出力するログソース名（例: sourcetype=fortigate*, access_combined 等）と検知すべきフィールド・値のヒント（例: subtype=vpn action=tunnel-up, uri_path=*/plugins/editors/jce* 等）。Step 3でSplunk SPLクエリ生成に使用する。

## 並び順（次ステップへの引き渡し順）
1. CISA KEV / ゼロデイ
2. CVSS 9.0以上 Critical
3. PoC公開済み
4. CVSS 7.5以上 High（RCE / 認証バイパス / 権限昇格）
5. 低優先度フラグ付き（参考B昇格候補）
