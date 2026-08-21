# pipeline-output-schema.md — レポートJSONスキーマ定義

## 概要

このファイルはレポート出力の基本形式である `security-report.json` のスキーマを定義する。
パイプラインは常にJSONを先に生成し、その後テキストに変換する。

**出力パス（日付ディレクトリ）**:
```
outputs/YYYY-MM-DD/
  YYYY-MM-DD-security-report.json                ← 基本形式・Section 1〜4 全データ（AI分析・機械処理用）★必須
  YYYY-MM-DD-security-report.txt                 ← 全セクション完全版 Section 1〜4
  YYYY-MM-DD-security-report-cve.txt             ← Section 3: 製品別CVE（ゼロデイ特報・本編・参考A・参考B・除外CVE）
  YYYY-MM-DD-security-report-zeroday-trends.txt  ← Section 2: ゼロデイ・トレンド（ゼロデイ特報・APT活動・注目CVE・攻撃予報）
  YYYY-MM-DD-security-report-ai.txt              ← Section 1: AI攻撃動向（本編・参考B・参考A・週次サマリー・除外）
  YYYY-MM-DD-security-report-soc.txt             ← Section 4: SOC推奨情報（高/中/低優先度・除外・集計）
```

計6ファイル（JSON 1 + テキスト 5）。全ファイルを outputs/YYYY-MM-DD/ に保存する。

---

## スキーマ全体構造

```json
{
  "meta": { ... },
  "zero_day_special": [ CVEエントリ ],
  "main_cve": [ CVEエントリ ],
  "reference_a": [ CVEエントリ ],
  "reference_b": [ CVEエントリ ],
  "trends": {
    "trends_cve": [ CVEエントリ（section_route: trends） ],
    "trends_topic": [ トレンド記事エントリ ]
  },
  "apt_main": [ APTエントリ ],
  "apt_notable": [ APTエントリ ],
  "forecasts": [ 予報エントリ ],
  "ai_attacks_main": [ AI攻撃エントリ ],
  "ai_attacks_reference_b": [ AI攻撃エントリ ],
  "ai_attacks_reference_a": [ AI攻撃エントリ ],
  "soc_recommendations": [ SOC推奨情報エントリ ],
  "exclusions": {
    "cve": [ 除外エントリ ],
    "apt": [ 除外エントリ ],
    "ai_attacks": [ 除外エントリ ],
    "soc_recommendations": [ 除外エントリ ]
  },
  "statistics": { ... }
}
```

`trends` はトップレベルの新設セクションであり、pipeline-1-cve.md のトラック B（`section_route: trends` タグ付きCVE）と
pipeline-2-trends.md が収集する一般トレンド記事（CVE未採番のゼロデイ・APT以外のキャンペーン動向等）を格納する。
既存の Section 2 テキスト出力（【ゼロデイ・セキュリティトレンド】内の「注目CVE（リスト外）」サブセクションおよび
トレンド記事）の内容と対応する。詳細は下記「trends オブジェクト」参照。

---

## info_id（収集情報の一意ID・全エントリ共通フィールド）

収集した情報（CVE / APT / AI攻撃 / SOC推奨情報 / トレンド記事の各エントリ）には、日をまたいだ横断分析・重複検知のための一意識別子 `info_id` を付与する。JSON専用フィールドであり、テキスト出力には含めない（他の `axis1_score` 等の JSON専用フィールドと同様の扱い）。

### フォーマット

```
YYYYMMDD-カテゴリ-ハッシュ値
例: 20260702-CVEP-232ffbaf
```

| 要素 | 内容 |
|---|---|
| YYYYMMDD | `meta.report_date` を `-` なしで8桁表記にしたもの |
| カテゴリ | 下表のカテゴリコード（英大文字4文字固定） |
| ハッシュ値 | SHA-256ハッシュの先頭8桁（16進小文字） |

### カテゴリコード表（全て4文字で統一）

| コード | 対象 | 該当する report_section / trends 配列 |
|---|---|---|
| `CVEP` | Section 3 製品別CVE（トラックA） | zero_day_special / main_cve / reference_a / reference_b |
| `CVET` | Section 2 注目CVE（トラックB） | trends.trends_cve |
| `TRND` | Section 2 トレンド記事 | trends.trends_topic |
| `APTC` | Section 2 APT活動 | apt_main / apt_notable |
| `AIAT` | Section 1 AI攻撃 | ai_attacks_main / ai_attacks_reference_a / ai_attacks_reference_b |
| `SOCR` | Section 4 SOC推奨情報 | soc_recommendations |

forecasts（予報）と observations（forecaster正規化データ）は「収集情報」ではなく本パイプラインの生成物・分析結果であるため対象外とする（既存の `forecast_id` / `observation_id` をそのまま使う）。

### ハッシュ入力の構成（案B: 日付＋タイトル＋主URL）

```
raw = "{YYYYMMDD}::{タイトル}::{主URL}"
ハッシュ値 = SHA256(raw の UTF-8バイト列) の先頭8桁（16進）
```

- **主URL**: そのエントリの `references[0].url`（配列の先頭要素）。参照が0件の場合は空文字列とする。
- **タイトル**: エントリ種別によって以下を使う（`title` フィールドを持たないCVE/APTエントリは代替の識別文字列を組み立てる）。

| エントリ種別 | タイトルの組み立て方 |
|---|---|
| CVEエントリ（zero_day_special / main_cve / reference_a / reference_b / trends.trends_cve） | `"{cve_id}/{product}"`（`cve_id` が null の場合は `"CVE未採番/{product}"`） |
| APTエントリ（apt_main / apt_notable） | `"{group_name}/{campaign_id}"` |
| AI攻撃エントリ（ai_attacks_*） | `title` フィールドをそのまま使用 |
| SOC推奨情報エントリ（soc_recommendations） | `title` フィールドをそのまま使用 |
| トレンド記事エントリ（trends.trends_topic） | `title` フィールドをそのまま使用 |

同一エントリを同日に再度JSON化しても同一の `info_id` が再現される（決定的生成）。翌日以降に同一事象が継続報告される場合、`report_date` が変わるため `info_id` も変わる（`info_id` は「その日その情報がどう記録されたか」の識別子であり、`cve_id` / `campaign_id` のような事象そのものの継続識別子ではない。事象の継続追跡は引き続き `cve_id` / `campaign_id` / `attack_id` / `rec_id` / `topic_id` を正とする）。

---

## meta オブジェクト

```json
"meta": {
  "schema_version": "1.0",
  "report_date": "YYYY-MM-DD",
  "generated_at": "YYYY-MM-DDTHH:MM:SS+09:00",
  "mode": 3,
  "mode_deprecated": true,
  "investigation_period": {
    "from": "YYYY-MM-DDTHH:MM:SS+09:00",
    "to":   "YYYY-MM-DDTHH:MM:SS+09:00"
  },
  "sweep": {
    "status": "ok",
    "threshold": 9.0,
    "kev_catalog_version": "YYYY.MM.DD",
    "candidates": 45,
    "handled": 45,
    "unhandled": 0,
    "kev_added_in_window": 1,
    "ghsa_origin_over_threshold": 6,
    "euvd": {
      "status": "ok",
      "added_candidates": 3
    }
  }
}
```

| フィールド | 型 | 説明 |
|---|---|---|
| schema_version | string | スキーマバージョン（固定: "1.0"） |
| report_date | string | レポート対象日 YYYY-MM-DD |
| generated_at | string | 生成日時 ISO 8601+09:00（タイムスタンプ規則は本ファイル末尾「タイムスタンプ規則」参照） |
| mode | integer | **非推奨（deprecated: true）**。モード選択は pipeline-3-weighting.md にて廃止済み・常に3固定。過去JSONとの後方互換性維持のためのみフィールドを残置し、新規ロジックでは参照しないこと |
| mode_deprecated | boolean | 常に true。mode フィールドが非推奨であることを機械可読に示す注記フラグ |
| investigation_period | object | 調査窓の開始・終了（ISO 8601、時刻・タイムゾーンオフセット必須） |
| sweep | object | 網羅スイープ（`scripts/nvd_window_sweep.py`）の母集団と突合結果。下記「meta.sweep」参照 |

### meta.sweep

Step 0.7 の網羅スイープと Step 3.9 の突合結果を記録する（SKILL.md 参照）。
**この記録はレポートの完全性を事後に検証可能にするためにある。**
値は突合コマンドの出力をそのまま転記し、推定値を書かないこと。

| フィールド | 型 | 説明 |
|---|---|---|
| status | string | `ok`（スイープ実行成功）/ `failed`（取得失敗・スイープ未実行）。`failed` の場合は他フィールドを null にし、Step 5 サマリーにも明記する |
| threshold | number | 列挙に使ったCVSS下限（既定 9.0）。判定は v3.1/v4.0/v3.0 の最大値 |
| kev_catalog_version | string | 参照した CISA KEV カタログ版（再現性確保のため必須） |
| candidates | integer | スイープ母集団の件数（`sweep_candidates`） |
| handled | integer | うちレポートに出現した件数（採用または除外記録済み） |
| unhandled | integer | 未処理件数。**Step 4 のコミット時点で 0 であること** |
| kev_added_in_window | integer | 窓内の CISA KEV 新規追加件数（観測出口クラス E1 の母集団） |
| ghsa_origin_over_threshold | integer | 閾値以上のうち GHSA 起点の件数（報道系ソースが構造的に落とす層の実測値） |
| euvd | object | EUVD 補完列挙の結果。`status`: `ok` / `failed`（EUVD のみ失敗・NVD+KEV で続行）/ `skipped`（`--no-euvd` 指定）。`added_candidates`: NVD/KEV に無く母集団へ追加された候補件数（スイープJSON `counts.euvd_added_candidates` を転記）。旧形式スイープ（EUVD 対応前）の再突合では省略可 |

`unhandled` が 0 でないレポートをコミットしてはならない。やむを得ず 0 にできない場合は、
残件と理由を除外サマリーへ記録したうえで Step 5 サマリーに明記する。

---

## CVEエントリ（zero_day_special / main_cve / reference_a / reference_b 共通）

```json
{
  "cve_id": "CVE-XXXX-XXXXX",
  "product": "製品名",
  "vendor": "ベンダー名",
  "affected_versions": "影響を受けるバージョン範囲の文字列",
  "priority": "critical",
  "cvss_v3": 9.8,
  "cvss_v4": null,
  "cvss_severity": "Critical",
  "cwe_ids": ["CWE-89"],
  "epss": {
    "score": 0.86,
    "percentile": 0.97,
    "model_date": "2026-06-26"
  },
  "status": {
    "kev_registered": true,
    "poc_published": true,
    "actively_exploited": true,
    "zero_day": false,
    "patch_available": true
  },
  "patch_info": {
    "available": true,
    "version": "12.3.2.4854",
    "eta": null
  },
  "fceb_deadline": "2026-06-26",
  "kev_date_added": "2026-06-24",
  "axis1_score": 10,
  "axis2_score": 7,
  "jpcert_ipa": {
    "issued": false,
    "entries": []
  },
  "changes_24h": [
    {
      "source": "BleepingComputer",
      "date": "2026-06-25T14:30:00+09:00",
      "description": "PoCの詳細技術解析が公開された"
    }
  ],
  "overview": "段落テキスト。改行なし。",
  "attack_flow": [
    { "step": 1, "description": "初期侵入の説明" },
    { "step": 2, "description": "横展開の説明" },
    { "step": 3, "description": "最終被害の説明" }
  ],
  "techniques": [
    {
      "technique_id": "T1190",
      "sub_technique_id": null,
      "tactic": "initial-access",
      "evidence": "ソースが明示する根拠の引用・要約（ソース名+日付を含む）"
    }
  ],
  "temp_mitigation": [],
  "ioc": {
    "confirmed": false,
    "ips": [],
    "domains": [],
    "hashes": [],
    "urls": [],
    "filenames": []
  },
  "monitoring": {
    "description": "監視対象ログソースと検知観点",
    "splunk_spl": [
      "index=wineventlog EventCode=4688 | stats count by Account_Name"
    ],
    "detection_notes": "判断ポイント・誤検知除外の考え方"
  },
  "references": [
    {
      "url": "https://example.com/article",
      "title": "記事タイトル（任意）",
      "language": "ja",
      "source": "Security NEXT"
    }
  ],
  "sector_impact": ["manufacturing", "government"],
  "region_impact": ["JP", "US"],
  "exploited_by": [],
  "section_route": "product_cve",
  "report_section": "main_cve",
  "info_id": "20260626-CVEP-a1b2c3d4"
}
```

### CVEエントリ フィールド定義

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| cve_id | string | "CVE-XXXX-XXXXX" |
| product | string | 製品名（日本語可） |
| vendor | string | ベンダー名 |
| affected_versions | string | 影響バージョン範囲（自由記述） |
| priority | string | "critical" / "high" / "medium" / "low" |
| cvss_v3 | number \| null | CVSS v3.x スコア（0.0〜10.0） |
| cvss_v4 | number \| null | CVSS v4.0 スコア（0.0〜10.0） |
| cvss_severity | string \| null | "Critical" / "High" / "Medium" / "Low" |
| cwe_ids | array[string] | ["CWE-89"] — 該当CWE ID。不明の場合は空配列 |
| epss.score | number \| null | EPSSスコア（0〜1・今後30日の実悪用観測確率）。取得不能はnull |
| epss.percentile | number \| null | EPSSパーセンタイル（0〜1・全CVE中の相対順位）。確度=高の定量ゲートD（M3）に使用 |
| epss.model_date | string \| null | EPSS算出日 YYYY-MM-DD（再現性確保用） |
| status.kev_registered | boolean | CISAのKEV登録済みか |
| status.poc_published | boolean | PoCが公開済みか |
| status.actively_exploited | boolean | 実悪用が確認されているか |
| status.zero_day | boolean | パッチ未提供または提供直後か |
| status.patch_available | boolean | パッチが利用可能か |
| patch_info.available | boolean | パッチ提供済みか |
| patch_info.version | string \| null | パッチ適用済みバージョン |
| patch_info.eta | string \| null | パッチ提供予定日（YYYY-MM-DD）|
| fceb_deadline | string \| null | CISA FCEB機関の対応期限（YYYY-MM-DD） |
| kev_date_added | string \| null | CISA KEVカタログへの登録日（YYYY-MM-DD）。KEV未登録の場合は null。予報エントリの `kev_snapshot.date_added` と同じ値の出典として使用する |
| axis1_score | integer | 軸1スコア（技術的深刻度） |
| axis2_score | integer | 軸2スコア（実環境影響度） |
| jpcert_ipa.issued | boolean | JPCERT/CCまたはIPAが24時間窓内に注意喚起を発行したか |
| jpcert_ipa.entries | array[{title, url}] | 発行済みの場合のタイトルとURL |
| changes_24h | array[{source, date, description}] | 24時間以内の変化。dateはISO 8601（+09:00・時刻まで）。時刻が情報源から判明しない場合は当日07:00+09:00（調査窓の基準時刻）を補完値として使用する |
| overview | string | 概要（自由テキスト。AI分析での文脈理解用） |
| attack_flow | array[{step, description}] | 攻撃の流れ（stepは1始まりの整数） |
| techniques | array[{technique_id, sub_technique_id, tactic, evidence}] | MITRE ATT&CK Technique（**情報源が明示する場合のみ**付与。ハルシネーション厳禁の原則に従い、判断不能な場合は空配列とする）。構造は `forecaster/schema/observation.schema.json` の `technique` 定義と同形: technique_id は "T\d{4}" 形式（親のみ）、sub_technique_id は "T\d{4}\.\d{3}" 形式またはnull、tactic は ATT&CK タクティック語彙、evidence はソース名+日付を含む根拠の要約 |
| temp_mitigation | array[string] | ゼロデイ特報のみ: 暫定緩和策の箇条書き |
| ioc.confirmed | boolean | IoCが確認されているか |
| ioc.ips | array[string] | C2・攻撃インフラのIPアドレス |
| ioc.domains | array[string] | ドメイン（[.]エスケープなしで記録） |
| ioc.hashes | array[string] | ファイルハッシュ（SHA256優先） |
| ioc.urls | array[string] | 完全URL形式のIoC |
| ioc.filenames | array[string] | 特徴的なファイル名 |
| monitoring.description | string | 監視対象ログソースと検知観点 |
| monitoring.splunk_spl | array[string] | SPLクエリ（1クエリ1要素） |
| monitoring.detection_notes | string | 判断ポイント・誤検知除外の考え方 |
| references | array[{url, title, language, source}] | 参照URL。language: "ja"/"en"/null |
| sector_impact | array[string] | 影響セクター（下記の制御語彙を使用） |
| region_impact | array[string] | 影響地域（"JP"/"US"/"global"等のISO 3166-1 alpha-2 or "global"） |
| exploited_by | array[string] | このCVEを悪用しているAPTのcampaign_id（cross-reference） |
| section_route | string | "product_cve"（pipeline-1-cve.md トラックA・Section 3 製品別CVE）/ "trends"（トラックB・`section_route: trends` タグ付き・Section 2 trends.trends_cve へ帰属）。pipeline-1-cve.md のトラックA/B排他的決定木の判定結果をそのまま記録する |
| report_section | string | "zero_day_special"/"main_cve"/"reference_a"/"reference_b"/"trends_cve"（section_route: trends のCVEが trends.trends_cve に格納される場合。振り分け先の本編/参考A/参考Bの区別は pipeline-3-weighting.md の軸1×軸2振り分けをtrends内でも適用し、値として保持する） |
| info_id | string | 収集情報の一意ID（"YYYYMMDD-CVEP-xxxxxxxx"）。生成規則は本ファイル冒頭の「info_id（収集情報の一意ID・全エントリ共通フィールド）」参照。JSON専用フィールド（テキスト非出力） |

**sector_impact 制御語彙**:
"government" / "finance" / "healthcare" / "manufacturing" / "telecom" / "energy" / "education" / "retail" / "it" / "professional_services" / "defense" / "critical_infrastructure" / "other"

---

## trends オブジェクト（trends.trends_cve / trends.trends_topic）

pipeline-2-trends.md が構成する Section 2【ゼロデイ・セキュリティトレンド】の観測材料を格納する。
JSON-first 原則（正規化ステージ 01 は JSON から observation を生成する）に従い、
Section 2 のテキスト出力に対応する構造化データをここに保持する。

```json
"trends": {
  "trends_cve": [
    {
      "cve_id": null,
      "product": "紐付け不能（製品単位に紐付かないキャンペーン）",
      "vendor": null,
      "affected_versions": null,
      "priority": "high",
      "cvss_v3": null,
      "cvss_v4": null,
      "cvss_severity": null,
      "cwe_ids": [],
      "epss": { "score": null, "percentile": null, "model_date": null },
      "status": {
        "kev_registered": false,
        "poc_published": true,
        "actively_exploited": true,
        "zero_day": true,
        "patch_available": false
      },
      "patch_info": { "available": false, "version": null, "eta": null },
      "fceb_deadline": null,
      "kev_date_added": null,
      "axis1_score": 9,
      "axis2_score": 3,
      "jpcert_ipa": { "issued": false, "entries": [] },
      "changes_24h": [
        {
          "source": "watchTowr Labs",
          "date": "2026-06-25T11:00:00+09:00",
          "description": "CVE未採番のゼロデイキャンペーンの詳細解析を公開"
        }
      ],
      "overview": "段落テキスト。改行なし。",
      "attack_flow": [
        { "step": 1, "description": "初期侵入の説明" }
      ],
      "techniques": [],
      "temp_mitigation": [],
      "ioc": { "confirmed": false, "ips": [], "domains": [], "hashes": [], "urls": [], "filenames": [] },
      "monitoring": { "description": "監視観点", "splunk_spl": [], "detection_notes": null },
      "references": [
        { "url": "https://labs.watchtowr.com/...", "title": null, "language": "en", "source": "watchTowr Labs" }
      ],
      "sector_impact": [],
      "region_impact": ["global"],
      "exploited_by": [],
      "section_route": "trends",
      "report_section": "trends_cve"
    }
  ],
  "trends_topic": [
    {
      "topic_id": "TREND-2026-06-25-001",
      "title": "トレンド記事のタイトル",
      "summary": "概要テキスト。改行なし。",
      "changes_24h": [
        {
          "source": "BleepingComputer",
          "date": "2026-06-25T13:00:00+09:00",
          "description": "24時間以内に確認された変化"
        }
      ],
      "sector_impact": [],
      "region_impact": ["global"],
      "references": [
        { "url": "https://www.bleepingcomputer.com/...", "title": null, "language": "en", "source": "BleepingComputer" }
      ],
      "report_section": "trends_topic",
      "info_id": "20260625-TRND-e5f6a7b8"
    }
  ]
}
```

### trends.trends_cve フィールド定義

CVEエントリ（zero_day_special / main_cve / reference_a / reference_b）と同一の型を使用する。
相違点のみ以下に示す:

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| cve_id | string \| null | CVE未採番の場合は null（例: CVE未採番のゼロデイ） |
| section_route | string | 常に "trends"（pipeline-1-cve.md トラックB由来であることを示す） |
| report_section | string | 常に "trends_cve" |
| axis1_score / axis2_score | integer | pipeline-3-weighting.md のCVE重みづけモデル（軸1×軸2）をそのまま適用し、本編/参考A/参考B相当の優先度をこの中で表現する（振り分け先の呼称はテキスト変換時に「注目CVE（リスト外）」内のランク表記として扱う） |
| info_id | string | カテゴリコードは `CVEP` ではなく `CVET` を使う（trends.trends_cve 専用コード）。生成規則は他は共通 |

後日CVEが採番され製品に紐付いた場合、pipeline-1-cve.md の規定により翌日以降の実行で
D2判定によりトラックA（Section 3・zero_day_special/main_cve/reference_a/reference_b のいずれか）へ
帰属し直す。reported-cves.md の備考に移行を記録する（pipeline-1-cve.md D3 節を参照）。

### trends.trends_topic フィールド定義

trends_topic は Section 2 に収録される「CVEに紐付かない一般トレンド記事・APT以外のキャンペーン動向」を格納する。
CVE型ともAPT型とも異なる軽量な型を使用する。

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| topic_id | string | "TREND-YYYY-MM-DD-NNN" 形式の一意ID |
| title | string | トレンド記事のタイトル |
| summary | string | 概要（自由テキスト。改行なし） |
| changes_24h | array[{source, date, description}] | 24時間以内の変化。dateはISO 8601（+09:00・時刻まで） |
| sector_impact | array[string] | CVEエントリと同じ制御語彙 |
| region_impact | array[string] | CVEエントリと同じ制御語彙 |
| references | array[{url, title, language, source}] | 参照URL |
| report_section | string | 常に "trends_topic" |
| info_id | string | 収集情報の一意ID（"YYYYMMDD-TRND-xxxxxxxx"）。生成規則は本ファイル冒頭の「info_id」節参照 |

---

## APTエントリ（apt_main / apt_notable 共通）

```json
{
  "group_name": "KongTuke",
  "aliases": [],
  "nation_state": null,
  "attribution_confidence": "low",
  "campaign_id": "KongTuke-2026-Mistic-IAB",
  "activity_type": ["new_malware", "active_campaign", "initial_access_broker"],
  "motivation": "financial",
  "first_seen": "2026-04-01",
  "last_seen": "2026-06-25",
  "targets": {
    "sectors": ["insurance", "education", "it", "professional_services"],
    "regions": [],
    "countries": []
  },
  "malware": [
    {
      "name": "Mistic",
      "type": "backdoor",
      "language": null,
      "delivery": ["dll_sideloading", "clickfix"],
      "persistence": ["fileless"],
      "c2_protocol": ["http"]
    }
  ],
  "axis_p_score": 6,
  "axis_q_score": 3,
  "changes_24h": [
    {
      "source": "Symantec",
      "date": "2026-06-24T10:00:00+09:00",
      "description": "初報: Misticバックドアの詳細技術分析を公開"
    }
  ],
  "overview": "段落テキスト。改行なし。",
  "attack_flow": [
    { "step": 1, "description": "ClickFix偽UIでPowerShell実行" },
    { "step": 2, "description": "MpExtMs.exeへDLLサイドローディングでMistic常駐化" },
    { "step": 3, "description": "6ランサムウェアグループにアクセス販売" }
  ],
  "ttps": [
    {
      "mitre_id": "T1574.002",
      "name": "DLL Side-Loading",
      "implementation": "MpExtMs.exe（Windows Defenderコンポーネント）を悪用"
    }
  ],
  "ioc": {
    "confirmed": true,
    "ips": [],
    "domains": ["api.telegram.org"],
    "hashes": [],
    "urls": [],
    "filenames": ["MpExtMs.dll"]
  },
  "recommended_actions": "対処内容の自由テキスト",
  "splunk_spl": [
    "index=wineventlog EventCode=7045 ImageLoaded=\"*MpExtMs*\" | stats count by ComputerName"
  ],
  "detection_notes": "判断ポイント",
  "references": [
    { "url": "https://...", "title": null, "language": "en", "source": "Symantec" }
  ],
  "related_cves": [],
  "report_section": "apt_notable",
  "info_id": "20260625-APTC-c9d0e1f2"
}
```

### APTエントリ フィールド定義

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| group_name | string | グループ名 |
| aliases | array[string] | 別名・MSTIC名・Mandiant名など |
| nation_state | string \| null | ISO 3166-1 alpha-2（"CN"/"RU"/"KP"/"IR"等）またはnull |
| attribution_confidence | string | "high" / "medium" / "low" / "unconfirmed" |
| campaign_id | string | 一意のキャンペーン識別子 |
| activity_type | array[string] | 下記の制御語彙から複数選択 |
| motivation | string | "espionage"/"financial"/"sabotage"/"hacktivism"/"unknown" |
| first_seen | string \| null | キャンペーン初観測日 YYYY-MM-DD |
| last_seen | string | 直近観測日 YYYY-MM-DD |
| targets.sectors | array[string] | CVEと同じsector_impact語彙 |
| targets.regions | array[string] | 地域（"Asia-Pacific"等の広域名も可） |
| targets.countries | array[string] | ISO 3166-1 alpha-2 |
| malware[].name | string | マルウェア名 |
| malware[].type | string | "backdoor"/"ransomware"/"infostealer"/"loader"/"dropper"/"rat"/"rootkit"/"wiper"/"other" |
| malware[].language | string \| null | 実装言語（"Rust"/"Go"/"C++"等） |
| malware[].delivery | array[string] | 配送手法（"dll_sideloading"/"phishing"/"clickfix"/"supply_chain"等） |
| malware[].persistence | array[string] | 永続化手法（"fileless"/"registry"/"scheduled_task"/"service"等） |
| malware[].c2_protocol | array[string] | C2通信プロトコル（"http"/"https"/"dns"/"telegram"等） |
| axis_p_score | integer | 軸Pスコア（信頼性・活動深刻度） |
| axis_q_score | integer | 軸Qスコア（キャンペーン規模・影響範囲） |
| ttps[].mitre_id | string | MITRE ATT&CK ID（例: "T1574.002"） |
| ttps[].name | string | テクニック名 |
| ttps[].implementation | string | 具体的な実装方法 |
| related_cves | array[string] | このグループが悪用しているCVE IDのリスト（cross-reference） |
| report_section | string | "apt_main" / "apt_notable" |
| info_id | string | 収集情報の一意ID（"YYYYMMDD-APTC-xxxxxxxx"）。タイトル要素は `"{group_name}/{campaign_id}"`。生成規則は本ファイル冒頭の「info_id」節参照 |

**activity_type 制御語彙**:
"new_malware" / "active_campaign" / "ttp_update" / "official_attribution" / "ioc_release" / "new_target" / "infrastructure_change" / "initial_access_broker" / "resume_activity"

---

## 予報エントリ（forecasts）

```json
{
  "forecast_number": 1,
  "title": "予報タイトル（防御側が何を優先すべきか）",
  "tier": 1,
  "confidence": "medium",
  "confidence_numeric": 0.5,
  "framing": "defensive_action",
  "outcome_channel": "E1",
  "window_hours": 72,
  "forecast_class": "fast_72h",
  "forecast_class_rationale": "KEV初回追加は72h窓で外部可視化されるため fast_72h に割当",
  "root": {
    "evidence": "確認済みEvidenceの記述",
    "past_patterns": "類似事象での過去観測",
    "threat_intel": "現在の脅威インテル"
  },
  "anchor": {
    "epss_score": 0.86,
    "epss_percentile": 0.97,
    "epss_model_date": "2026-06-26",
    "kev_registered": true,
    "ssvc_decision": "Act",
    "ssvc_automatable": "yes"
  },
  "kev_snapshot": {
    "date_added": "2026-06-25",
    "ransomware_flag": "Known",
    "reference_set": ["https://www.cisa.gov/..."]
  },
  "estimated_part": "推定部分の記述（なければnull）",
  "early_warning_signals": "先回り監視シグナルの記述",
  "hit_criteria": "的中判定条件（観測出口クラスE1〜E4の一次・二値イベント）",
  "deadline_date": "2026-06-30",
  "related_cves": [],
  "related_apt_campaigns": ["KongTuke-2026-Mistic-IAB"]
}
```

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| forecast_number | integer | 1始まりの連番 |
| title | string | 予報タイトル |
| tier | integer | 1 / 2 / 3（pipeline-forecast-verification.md 定義準拠） |
| confidence | string | "high" / "medium" / "low" |
| confidence_numeric | number | high=0.8 / medium=0.5 / low=0.3（AI分析での定量化用）。**注意**: これはレポート項目のAI分析用定量化値であり、予報の確度キャリブレーション（Brierスコア用代表確率: 高0.75/中0.55/低0.30、pipeline-forecast-verification.md 定義）とは別体系。予報の採点・較正には後者を正とする |
| framing | string | "defensive_action" / "attacker_behavior" |
| outcome_channel | string | **M1**: 的中条件の観測出口クラス "E1"（KEV初回追加）/"E2"（新規IOC公開）/"E3"（CERT初回勧告）/"E4"（PoC公開）。"E5"（スキャン増）は予約値で的中主条件には未使用 |
| window_hours | integer | **M2**: 検証窓（72 または 168以上） |
| forecast_class | string | **M2**: "fast_72h"（KEV初回追加・IOC公開・PoC公開・進行中攻撃）/ "slow_7d"（外部報道依存の主題） |
| forecast_class_rationale | string | **M2ガード3**: forecast_class 割当根拠（発行時に1行・検証時のトラック移動禁止） |
| anchor.epss_score | number \| null | **M3**: EPSSスコア（0〜1）。取得不能はnull |
| anchor.epss_percentile | number \| null | **M3**: EPSSパーセンタイル（0〜1）。確度=高は≥0.95 AND KEV |
| anchor.epss_model_date | string \| null | **M3**: EPSS算出日 YYYY-MM-DD（再現性確保） |
| anchor.kev_registered | boolean | **M3**: 発行時点のKEV登録状態 |
| anchor.ssvc_decision | string | **M3**: SSVC決定 "Act"/"Attend"/"Track"/"Track*"。確度=高はAct/Attend |
| anchor.ssvc_automatable | string | **M3**: SSVC Automatable "yes"/"no"。"no"（ASLR回避・認証・多段要）は確度=高から自動降格 |
| kev_snapshot.date_added | string \| null | **M4**: 発行時KEVの dateAdded。検証時に再登録（変化なし）を非的中判別する |
| kev_snapshot.ransomware_flag | string \| null | **M4**: "Known"/"Unknown"。Unknown→Known変化は的中構成要素 |
| kev_snapshot.reference_set | array[string] | **M4**: 発行時KEV参照URLセット。新規参照追加の検出に使う |
| estimated_part | string \| null | 推定部分（根拠十分なT1純粋継続予報はnull） |
| early_warning_signals | string | 先回り監視シグナル |
| hit_criteria | string | 的中判定条件（outcome_channel の一次イベントに紐付ける） |
| deadline_date | string \| null | **M2ガード2**: slow_7d予報の確定期限日（発行+7日）。期限超過の未確定は自動「外れ」 |
| related_cves | array[string] | 関連するCVE ID |
| related_apt_campaigns | array[string] | 関連するcampaign_id |

---

## AI攻撃エントリ（ai_attacks_main / ai_attacks_reference_b / ai_attacks_reference_a 共通）

```json
{
  "attack_id": "AI-2026-06-25-001",
  "title": "インシデント名または研究名",
  "category": "B",
  "subcategory": "B1",
  "attacker_type": "nation_state",
  "adoption_triggers": ["A-P", "A-Q"],
  "atlas_ids": ["AML.T0043"],
  "owasp_llm": ["LLM01"],
  "owasp_agentic": [],
  "targets": {
    "sectors": ["it"],
    "regions": ["global"],
    "countries": []
  },
  "damage_scale": "組織数・金額等の判明分（不明の場合はnull）",
  "burst_count": 4,
  "burst_status": "threshold_met",
  "axis_x_score": 8,
  "axis_y_score": 5,
  "changes_24h": [
    {
      "source": "SentinelOne",
      "date": "2026-06-23T09:00:00+09:00",
      "description": "macOS.GaslightのAIプロンプトインジェクション回避機能を詳報"
    }
  ],
  "overview": "概要テキスト",
  "attack_flow": [
    { "step": 1, "description": "..." },
    { "step": 2, "description": "..." }
  ],
  "ioc_signals": {
    "confirmed": true,
    "domains": ["api.telegram.org"],
    "hashes": [],
    "detection_signals": ["Telegram公式アプリ以外からのapi.telegram.orgへの接続"]
  },
  "monitoring": {
    "description": "監視観点",
    "splunk_spl": ["index=macos_logs ..."],
    "detection_notes": "判断ポイント"
  },
  "references": [
    { "url": "https://...", "title": null, "language": "en", "source": "SentinelOne" }
  ],
  "report_section": "ai_attacks_main",
  "info_id": "20260625-AIAT-f1a2b3c4"
}
```

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| attack_id | string | "AI-YYYY-MM-DD-NNN" 形式の一意ID |
| title | string | インシデント・研究・CVEの名称 |
| category | string | "A" / "B" / "C"（pipeline-ai-1.md のカテゴリ定義） |
| subcategory | string | "A1"〜"A6" / "B1"〜"B6" / "C1"〜"C6" |
| attacker_type | string | "criminal_org" / "nation_state" / "researcher" / "unknown" |
| adoption_triggers | array[string] | A-P/A-Q/A-R/A-S/A-T/A-U/A-V/A-W/A-X/A-Y 形式（pipeline-ai-1.md の採用条件。旧 P〜Y 単独記号から改名。過去JSON中の単独記号表記は後方互換として許容するが、新規出力は A- 接頭辞付き形式のみを使用する） |
| atlas_ids | array[string] | MITRE ATLAS ID（"AML.Txxxx"形式） |
| owasp_llm | array[string] | OWASP LLM Top 10 ID（"LLM01"等） |
| owasp_agentic | array[string] | OWASP Agentic Top 10 ID（"AG01"等） |
| damage_scale | string \| null | 被害規模の記述（金額・件数・組織数等） |
| burst_count | integer | 48時間以内の独立ソース数 |
| burst_status | string | "below_threshold"（3件未満）/"threshold_met"（3〜5件）/"burst_exceeded"（6件以上） |
| axis_x_score | integer | 軸Xスコア（実証・悪用深刻度） |
| axis_y_score | integer | 軸Yスコア（影響範囲・実害） |
| ioc_signals.confirmed | boolean | IoC・検知シグナルが確認されているか |
| ioc_signals.detection_signals | array[string] | プロンプトパターン・行動的シグナル等 |
| report_section | string | "ai_attacks_main"/"ai_attacks_reference_b"/"ai_attacks_reference_a" |
| info_id | string | 収集情報の一意ID（"YYYYMMDD-AIAT-xxxxxxxx"）。タイトル要素は `title` フィールドをそのまま使用。生成規則は本ファイル冒頭の「info_id」節参照 |

---

## SOC推奨情報エントリ（soc_recommendations）

```json
{
  "rec_id": "SOC-2026-06-26-001",
  "title": "エントリのタイトル",
  "perspective": "cve",
  "adoption_triggers": ["β", "γ"],
  "priority": "high",
  "product_or_service": "製品名 / サービス名（該当なしの場合はnull）",
  "targets": {
    "sectors": ["finance", "government"],
    "regions": ["JP"]
  },
  "changes_24h": [
    {
      "source": "JPCERT/CC",
      "date": "2026-06-26T08:00:00+09:00",
      "description": "24時間内に確認された変化"
    }
  ],
  "overview": "概要テキスト。改行なし。",
  "recommended_actions": [
    "SOCとして取るべき具体的なアクション1",
    "アクション2"
  ],
  "monitoring": {
    "description": "監視観点（オプション）",
    "splunk_spl": [],
    "detection_notes": null
  },
  "references": [
    { "url": "https://example.com", "title": null, "language": "ja", "source": "JPCERT/CC" }
  ],
  "info_id": "20260626-SOCR-a7b8c9d0"
}
```

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| rec_id | string | "SOC-YYYY-MM-DD-NNN" 形式の一意ID |
| title | string | エントリのタイトル |
| perspective | string | "cve" / "zeroday" / "ai_attack"（pipeline-soc-recommend.md の観点区分） |
| adoption_triggers | array[string] | α〜η（pipeline-soc-recommend.md の採用条件） |
| priority | string | "high" / "medium" / "low" |
| product_or_service | string \| null | 対象製品・サービス名。なければ null |
| recommended_actions | array[string] | SOCが取るべき具体的アクションのリスト |
| monitoring.splunk_spl | array[string] | SPLクエリ（オプション。なければ空配列） |
| info_id | string | 収集情報の一意ID（"YYYYMMDD-SOCR-xxxxxxxx"）。タイトル要素は `title` フィールドをそのまま使用。生成規則は本ファイル冒頭の「info_id」節参照 |

---

## 除外エントリ（exclusions.cve / exclusions.apt / exclusions.ai_attacks / exclusions.soc_recommendations）

```json
{
  "cve_id": "CVE-2026-20230",
  "product": "Cisco UCM",
  "reason": "already_reported",
  "reason_detail": null,
  "reported_date": "2026-06-24"
}
```

```json
{
  "campaign_id": "NightmareEclipse-2026-WindowsZeroDayDisclosure",
  "group_name": "Nightmare Eclipse",
  "reason": "already_reported",
  "reason_detail": null,
  "reported_date": "2026-06-24"
}
```

```json
{
  "attack_id": null,
  "title": "インシデント名",
  "reason": "no_change",
  "reported_date": "2026-06-23"
}
```

**reason 制御語彙**:
"already_reported" / "no_change" / "insufficient_evidence" / "out_of_window" / "low_score"

---

## statistics オブジェクト

```json
"statistics": {
  "cve": {
    "zero_day": 0,
    "main": 0,
    "reference_a": 1,
    "reference_b": 2,
    "excluded": 11,
    "total_processed": 14
  },
  "apt": {
    "main": 0,
    "notable": 2,
    "excluded": 2,
    "total_processed": 4
  },
  "ai_attacks": {
    "main": 0,
    "reference_a": 0,
    "reference_b": 0,
    "excluded": 0,
    "total_processed": 0,
    "category_breakdown": {
      "A": 0,
      "B": 0,
      "C": 0
    }
  },
  "soc_recommendations": {
    "high": 0,
    "medium": 0,
    "low": 0,
    "excluded": 0,
    "total_processed": 0,
    "perspective_breakdown": {
      "cve": 0,
      "zeroday": 0,
      "ai_attack": 0
    }
  }
}
```

---

## JSONからテキストへの変換ルール

JSONをテキストに変換する際は以下のマッピングに従う。フォーマットの詳細は `pipeline-3-weighting.md` と `pipeline-report-modes.md` のテンプレートに従う。

| JSONフィールド | テキスト出力先 |
|---|---|
| meta.report_date / generated_at | ヘッダー（調査日時・調査期間） |
| zero_day_special | 【ゼロデイ特報】セクション |
| main_cve | 【本編】セクション |
| reference_a | 【参考情報A】セクション |
| reference_b | 【参考情報B】セクション |
| trends.trends_cve | 【ゼロデイ・トレンド】内「注目CVE（リスト外）」サブセクション |
| trends.trends_topic | 【ゼロデイ・トレンド】内トレンド記事サブセクション |
| apt_main | 【APT活動—本編】セクション |
| apt_notable | 【APT活動—注目動向】セクション |
| forecasts | 【攻撃予報】セクション |
| ai_attacks_main | 【AI攻撃—本編】セクション |
| ai_attacks_reference_b | 【AI攻撃—参考B】セクション |
| ai_attacks_reference_a | 【AI攻撃—参考A】セクション |
| soc_recommendations | 【SOC推奨情報】セクション（security-report-soc.txt / security-report.txt） |
| exclusions | 【除外サマリー】セクション |
| statistics | 本日の集計行 |

### テキストファイル別の収録セクション

| ファイル | 収録セクション |
|----------|---------------|
| security-report.txt | Section 1〜4 全セクション + 除外サマリー + 集計行 |
| security-report-cve.txt | Section 3（製品別CVE）: zero_day_special / main_cve / reference_a / reference_b / exclusions.cve / statistics.cve |
| security-report-zeroday-trends.txt | Section 2（ゼロデイ・トレンド）: zero_day_special / trends.trends_cve / trends.trends_topic / apt_main / apt_notable / forecasts / exclusions.apt / statistics.apt |
| security-report-ai.txt | Section 1（AI攻撃）: ai_attacks_main / ai_attacks_reference_b / ai_attacks_reference_a / exclusions.ai_attacks / statistics.ai_attacks |
| security-report-soc.txt | Section 4（SOC推奨）: soc_recommendations（priority順）/ exclusions.soc_recommendations / statistics.soc_recommendations |

### 変換時の注意点

- `cve_id` が null の場合（インシデント報告等）は「（インシデント報告・CVE未割当）」と表記する
- `status` オブジェクトは True のフラグのみを「KEV登録済み / 実悪用確認 / PoC公開 / ゼロデイ」形式で列挙する
- `attack_flow` の各要素は「1. 〜 / 2. 〜 / 3. 〜」の番号付きステップとして出力する
- `ioc.confirmed = false` の場合は「IoC: 確認されず」と出力する
- `monitoring.splunk_spl` の各要素はコードブロックなし・1行で出力する
- `confidence_numeric` はテキストには出力しない（JSON専用フィールド）
- `axis1_score` / `axis2_score` / `axis_p_score` / `axis_q_score` はテキストには出力しない（JSON専用フィールド）
- `report_section` フィールドはテキストには出力しない（JSON専用フィールド）
- `info_id` フィールドはテキストには出力しない（JSON専用フィールド。生成規則は本ファイル冒頭の「info_id」節参照）
- 予報の `outcome_channel` / `forecast_class` / `window_hours` はテキストに出力する（【攻撃予報】の「観測出口クラス:」「検証窓:」行。pipeline-3-weighting.md テンプレート参照）
- 予報の `anchor` / `kev_snapshot` / `forecast_class_rationale` / `deadline_date` はテキストには出力しない（JSON専用・検証ステージが使用）
- CVEの `epss.score` / `epss.percentile` / `epss.model_date` はテキストには出力しない（JSON専用・確度アンカー算出用）
- `references` 配列は URL のみ行頭から出力する（title/language/sourceはテキスト非出力）

---

## 利用例（AI分析向け）

このJSONは以下のような分析用途での利用を想定している:

- 複数日分のJSONを結合して脅威トレンドの時系列分析を行う
- `sector_impact` / `region_impact` / `targets.sectors` を集計して業種・地域別の脅威マップを生成する
- `exploited_by` / `related_cves` のcross-referenceを使ってCVE-APT間の関係グラフを構築する
- `confidence_numeric` と `tier` を使って予報の精度評価を定量化する
- `burst_status` / `axis_x_score` / `axis_y_score` によるAI攻撃の優先度フィルタリングを行う
- `ttps[].mitre_id` を集計してATT&CKカバレッジマップを作成する
- `malware[].c2_protocol` / `malware[].delivery` を横断分析してTTP変化を追跡する

---

## トークン使用量ファイル（token-usage.json）

`outputs/YYYY-MM-DD/YYYY-MM-DD-token-usage.json` は**レポートではなく実行コストの運用メタ情報**である。
`scripts/token_usage_report.py` が生成し、テキスト変換ファイルには含めない。

```json
{
  "measured_at": "YYYY-MM-DDTHH:MM:SS+09:00",
  "label": "daily report YYYY-MM-DD",
  "session_ids": ["..."],
  "transcripts": ["..."],
  "first_message_at": "YYYY-MM-DDTHH:MM:SS+09:00",
  "last_message_at": "YYYY-MM-DDTHH:MM:SS+09:00",
  "api_requests": 283,
  "tokens": {
    "input": 0, "cache_write_5m": 0, "cache_write_1h": 0,
    "cache_read": 0, "output": 0, "total": 0
  },
  "server_tools": { "web_search_requests": 0, "web_fetch_requests": 0, "cost_usd": 0.0 },
  "cost_usd": { "input": 0.0, "cache_write": 0.0, "cache_read": 0.0, "output": 0.0,
                "total": 0.0, "server_tools": 0.0, "grand_total": 0.0 },
  "cost_jpy": null,
  "jpy_rate": null,
  "cost_is_complete": true,
  "by_model": { "<model-id>": { "api_requests": 0, "tokens": {}, "cost_usd": {}, "priced": true } },
  "notes": ["..."]
}
```

| フィールド | 型 | 説明 |
|---|---|---|
| measured_at | string | 計測時刻（このスクリプト実行時点のスナップショット。以降の処理分は含まない） |
| label | string | 実行ラベル（日次は `daily report YYYY-MM-DD`） |
| session_ids / transcripts | array | 集計対象のセッションID・トランスクリプトパス（サブエージェント分を含む） |
| api_requests | integer | 重複排除後のAPI呼び出し回数 |
| tokens | object | 入力 / キャッシュ書込(5m・1h) / キャッシュ読出 / 出力 / 合計 |
| cost_usd | object | 上記内訳ごとの料金概算とサーバーツール込みの総額 |
| cost_is_complete | boolean | 単価未登録モデルが混在した場合 false（総額が過小になる） |
| by_model | object | モデル別内訳。`priced: false` は単価未登録 |

- **料金は Anthropic 公開単価に基づく概算**であり、定額プラン利用時の実請求額とは一致しない
- 計測は commit 前に1回だけ行い、PR本文・チャット報告では保存済み JSON を
  `--from-json` で再描画して数値を一致させる
