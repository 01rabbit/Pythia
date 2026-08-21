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

★ソース巡回に先立ち、後述「網羅スイープ」の機械列挙で母集団を確定させること。
下記のソース名を列挙するだけでは GHSA / VulnCheck / MITRE 起点のCVEは構造的に拾えない。

1. CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
2. NVD: https://nvd.nist.gov/
3. CVE Program（一次レコード）: https://www.cve.org/
   - NVD の分析・スコアリング完了前のレコード確認に使用する（新規採番直後のCVEはNVDに反映が遅れる場合がある）。
4. EUVD（ENISA EU Vulnerability Database）: https://euvd.enisa.europa.eu/
   - ENISA が NIS2 指令に基づき運営する脆弱性DB。MITRE CVE / NVD / GHSA / 各国CSIRT を
     集約し、独自の EUVD ID（`EUVD-YYYY-NNNNN`）を採番する。API・機械可読データあり
     （https://euvdservices.enisa.europa.eu/api — 連続アクセスは 403 になるため要スロットリング）。
   - **用途1（NVD 冗長化）**: NVD の分析遅延・障害時も CNA 提供スコア付きレコードを返すため、
     NVD 未反映CVEのスコア・影響製品確認に使用する（NVD 反映前のCVEを EUVD が先に
     掲載する事例を 2026-08-21 に実測済み）。CVSS は引き続き **NVD を正とし**、
     NVD 未掲載の間のみ EUVD 記載の CNA スコアを暫定値として使用し出典を明記する。
   - **用途2（GHSA 勧告の窓内変化検出）**: NVD 公開日が古いCVEでも、GHSA 勧告が窓内に
     新規公開されると EUVD 側の公開日は窓内になる（採用条件 G の変化検出を補完）。
   - **用途3（CVE未採番レコードの捕捉）**: CVE エイリアスを持たないレコードは
     EUVD ID を識別子として扱う（報告時も EUVD ID を記録する）。
   - ★注意: EUVD の exploited フラグは大半が CISA KEV 由来の集約であり、
     **独立した悪用観測シグナルとして扱わない**。exploitation_stage の根拠には
     EUVD が参照する一次ソースを必ず照合する。観測出口チャネル E1 の正は
     引き続き CISA KEV であり、EUVD exploited を的中判定に使用しない
     （pipeline-forecast-verification.md の hit_criteria を変更しない）。
   - スイープ（Step 0.7）が EUVD 補完列挙を機械実行する（下記「網羅スイープ」節）。
5. GitHub Advisory Database: https://github.com/advisories
6. OSV（OSS脆弱性DB）: https://osv.dev/
   - OSS はエコシステム・パッケージ・バージョン・コミット単位で照合できるため、
     ライブラリ・依存関係系CVEの影響バージョン特定に優先使用する。API・機械可読データあり。
7. JVN / JVN iPedia（国内製品・国内ベンダー照合）: https://jvn.jp/ / https://jvndb.jvn.jp/
   - 国内製品・国内ベンダーに関わるCVEは JVN iPedia で日本語情報・国内アドバイザリの有無を照合する。
   - プログラム照会には MyJVN API（https://jvndb.jvn.jp/apis/myjvn/index.html）を使用できる。
   - JVN iPedia 新着は security-intel-collector/feeds.json で機械収集済み（data/raw/ を一次入力とする）。
8. ベンダーアドバイザリ（Fortinet / Palo Alto / Ivanti / Microsoft / Cisco / Oracle 等）
9. BleepingComputer / The Hacker News / SecurityWeek
10. PoC情報: GitHub / Exploit-DB / Packet Storm / watchTowr / ProjectDiscovery
11. EPSS（Exploit Prediction Scoring System・FIRST.org）: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX
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
- **後述「網羅スイープ」の母集団に含まれるCVEは、採用しない場合も除外サマリーへ
  理由付きで記録する**（記録の免除規定は設けない。理由は同節「記録義務を課す理由」参照）
- 採用済みCVEについては製品・種別を問わず足切り禁止
- 以下は除外ではなく `低優先度` フラグを付けて次ステップへ渡す:
  - CVSS 7.0未満 かつ KEV非登録 かつ PoC非公開
  - DoSのみ CVSS 8.0未満
  - 情報漏洩のみ CVSS 8.0未満

---

## 網羅スイープ（必須）

報道系ソースの巡回だけでは調査窓内のCVE母集団が確定しないため、**Step 1 の収集を始める前に
機械列挙を1回実行し、その出力を候補集合の起点とする**（SKILL.md Step 0.7）。

### スイープの実行

```bash
# 窓内に新規公開された CVSS 9.0以上 + CISA KEV 窓内追加 + EUVD 補完を全件列挙
python3 scripts/nvd_window_sweep.py \
  --window-start "${WINDOW_START}" --window-end "${WINDOW_END}" \
  --output ".cache/daily-security-intel/${TODAY}/step1-sweep.json"
```

- 入力の `WINDOW_START` / `WINDOW_END` は **JST**（`"2026-08-18 07:00"` 形式）。
  スクリプトが内部でUTCへ変換して NVD へ渡す
- 出力の Markdown 表はそのまま Step 1 サブエージェントへの指示文に貼ってよい
- `--threshold` で下限を変更できる（既定 9.0）。国内シグナルが濃い日や
  スポット監査では `--threshold 7.0` も使う
- 依存は標準ライブラリのみ。`NVD_API_KEY` を設定するとレート制限が緩和される
- 出力先は `.cache/`（Git 追跡対象外）。このスクリプトは `forecaster/knowledge/` を
  一切書き換えない（CLAUDE.md 行動原則5）

### 記録義務を課す理由

「トラック採用条件に非該当のCVEは除外サマリー記載不要」という運用にすると、
**取りこぼしと意図的な不採用が事後に区別できなくなる**。

姉妹リポジトリ（security-intel / fdns-intel）の 2026-08-04〜07 の窓では、以下9件が
レポート本体にも除外サマリーにも一切現れないことが実測で判明した
（CVSS 9.0以上が5件、公開PoCありを含む）:
Misskey (v4.0 9.2・GHSA起点) / OpenEMR (v4.0 9.4・VulnCheck起点) /
osTicket (v3.1 9.8・MITRE起点) / kotaemon (v3.1 9.8・VulnCheck起点) /
Flowise (v4.0 9.2・GHSA起点) / Grav CMS / Apache Airflow (v3.1 9.8・公開PoCあり) ほか。

いずれも GHSA / VulnCheck / MITRE 起点の OSS 系で、BleepingComputer /
The Hacker News / SecurityWeek には載らない。**調査ソースに「GitHub Advisory
Database」と名前を書くだけでは構造的に拾えない**ため、機械列挙を必須とする。

Pythia 本リポジトリでも 2026-08-18 の窓で同種の欠損を実測している
（スイープ候補45件のうちレポートに出現1件・未処理44件、うち GHSA 起点6件）。

### Pythia において取りこぼしが予報を歪める経路

観測の取りこぼしは、単にレポートの網羅性が落ちるだけの問題ではない。

1. 日次レポート JSON → `forecaster/observations/` へ正規化（01-normalize）
2. observations 全履歴 → ベースライン統計 `technique-freq` / `group-activity`（02-baseline）
3. ベースライン・実測アンカー → 予報の `base_rate_estimate` と確度（03-forecast）

収集が特定の情報源クラス（報道系）に偏ると、**観測母集団そのものが偏り、
ベースラインと base_rate が系統的に歪む**。予報の確度は歪んだ分布の上に乗るため、
検証ループ（04-verify）では「予報ロジックの誤り」と「観測母集団の欠損」を区別できない。
さらに E1（CISA KEV 初回追加）は主要な観測出口チャネルであり、
窓内 KEV 追加の全件把握は的中判定の前提条件である。

### スイープが依拠する仕様（変更時の注意）

- **NVD の severity フィルタは使わない**。公開直後（`vulnStatus: Received`）のCVEは
  NVD一次評価が未付与で、`cvssV3Severity=CRITICAL` 等が CNA 提供スコアと噛み合わない。
  実測では同フィルタが2件しか返さず（うち1件は実スコア7.4）、
  osTicket 9.8 / kotaemon 9.8 / OpenEMR 9.4 / Misskey 9.2 が全て欠落した。
  **フィルタなしで全件取得し、閾値判定はクライアント側で行う**
- **CVSS v2 は閾値判定に使わない**。v2 の 10.0 は v3.1/v4.0 の Critical と等価ではなく、
  v2 しか付いていない古いCNAのCVEを大量に拾ってノイズになる。
  判定は v3.1 / v4.0 / v3.0 のうち最大値で行う
- **`lastModStartDate` トラックは既定で使わない**。NVD は古いCVEの CPE 付与・参照整理で
  日常的に数千件を更新するため、ノイズが支配的になる（実測で2,507件、
  うち Linux kernel 一括再更新216件・2024年以前の KEV 既報CVEが多数）。
  実務上重要な「KEV 新規追加」は KEV カタログ側から別途拾う。
  監査目的で必要なときのみ `--include-modified` を付ける
- **アグリゲータCNA はバッチ集約してはならない**。GHSA / MITRE / VulDB / VulnCheck /
  CERT/CC / HackerOne / WPScan 等は複数ベンダーのCVEを横断的に採番するため、
  件数が多くても「同一ベンダーの同一リリース」ではない。集約すると
  **まさに取りこぼしたCVEが代表1件の影に消える**（実測で GHSA 採番12件の中に
  Misskey / kotaemon / Flowise / OpenSIPS / Sequelize という無関係な製品が同居していた）。
  単一ベンダーPSIRT が同一窓で5件以上を一括公開したかたまりのみ集約してよい
- **EUVD 補完列挙はフェイルソフト**。スイープは NVD+KEV に加えて EUVD
  （ENISA EU Vulnerability Database）を補完列挙し、NVD 窓内母集団に無いレコードのみ
  `euvd_added` 候補として母集団へ追加する（NVD と重複するCVEは重複計上しない）。
  EUVD の取得失敗はスイープ全体を失敗させず、`euvd.status: failed` を記録して
  NVD+KEV のみで続行する（`--no-euvd` でスキップも可）。EUVD 候補もバッチ集約禁止
  （必ず個別判断に回す）。CVE 未採番の候補は **EUVD ID をレポートに記録**して突合を通す
- **EUVD の時刻は UTC として解釈し、窓判定はクライアント側で行う**。EUVD API の
  fromDate/toDate は日付粒度のため前後1日広げて取得し、`datePublished` で窓判定する。
  API はタイムゾーンを明示しないため（NVD 公開時刻との突合で UTC と判断・
  CVE-2026-72529 で実測）、境界のずれは候補の過剰包含側に倒す
- **EUVD の exploited は独立シグナルではない**。大半が CISA KEV 由来の集約のため、
  KEV 掲載済みCVEの exploited は候補化しない（E1 の正は CISA KEV）。KEV に無い
  exploited のみ `euvd_exploited_in_window` として候補化し、採用判断時は
  EUVD が参照する一次ソースを照合する

### 母集団の処理義務（完全性チェック）

スイープ母集団の各CVEは、**採用 / 除外サマリーへの理由付き記録 / バッチ集約**の
いずれかに必ず割り当てる。Step 3 のJSON生成後に突合を実行し、未処理0件を確認する:

```bash
python3 scripts/nvd_window_sweep.py \
  --from-json ".cache/daily-security-intel/${TODAY}/step1-sweep.json" \
  --reconcile "outputs/${TODAY}/${TODAY}-security-report.json"
```

未処理があると終了コード1で未処理一覧を出力する。未処理を解消してから Step 4 へ進む
（SKILL.md Step 3.9）。

**注意: 突合は「レポート JSON 全文にそのCVE IDが1度でも現れるか」だけを見る。**
除外サマリーへ理由なしでCVE IDを並べれば突合は通ってしまうため、
突合の通過は完全性の必要条件であって十分条件ではない。除外には必ず理由を書くこと。

---

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
