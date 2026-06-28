# pipeline-output-schema.md — レポートJSONスキーマ定義

## 概要

このファイルはレポート出力の基本形式である `security-report.json` のスキーマを定義する。
パイプラインは常にJSONを先に生成し、その後テキストに変換する。

**出力パス（日付ディレクトリ）**:
```
outputs/YYYY-MM-DD/
  YYYY-MM-DD-security-report.json                ← 基本形式・Section 1〜4 全データ（AI分析・機械処理用）★必須
  YYYY-MM-DD-security-report.txt                 ← 全セクション完全版 Section 1〜4（Slack共有向け）
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

---

## meta オブジェクト

```json
"meta": {
  "schema_version": "1.0",
  "report_date": "YYYY-MM-DD",
  "generated_at": "YYYY-MM-DDTHH:MM:SS+09:00",
  "mode": 3,
  "investigation_period": {
    "from": "YYYY-MM-DDTHH:MM:SS+09:00",
    "to":   "YYYY-MM-DDTHH:MM:SS+09:00"
  }
}
```

| フィールド | 型 | 説明 |
|---|---|---|
| schema_version | string | スキーマバージョン（固定: "1.0"） |
| report_date | string | レポート対象日 YYYY-MM-DD |
| generated_at | string | 生成日時 ISO 8601+09:00 |
| mode | integer | 1 / 2 / 3 |
| investigation_period | object | 調査窓の開始・終了（ISO 8601） |

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
  "axis1_score": 10,
  "axis2_score": 7,
  "jpcert_ipa": {
    "issued": false,
    "entries": []
  },
  "changes_24h": [
    {
      "source": "BleepingComputer",
      "date": "2026-06-25",
      "description": "PoCの詳細技術解析が公開された"
    }
  ],
  "overview": "段落テキスト。改行なし。",
  "attack_flow": [
    { "step": 1, "description": "初期侵入の説明" },
    { "step": 2, "description": "横展開の説明" },
    { "step": 3, "description": "最終被害の説明" }
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
  "report_section": "main_cve"
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
| status.kev_registered | boolean | CISAのKEV登録済みか |
| status.poc_published | boolean | PoCが公開済みか |
| status.actively_exploited | boolean | 実悪用が確認されているか |
| status.zero_day | boolean | パッチ未提供または提供直後か |
| status.patch_available | boolean | パッチが利用可能か |
| patch_info.available | boolean | パッチ提供済みか |
| patch_info.version | string \| null | パッチ適用済みバージョン |
| patch_info.eta | string \| null | パッチ提供予定日（YYYY-MM-DD）|
| fceb_deadline | string \| null | CISA FCEB機関の対応期限（YYYY-MM-DD） |
| axis1_score | integer | 軸1スコア（技術的深刻度） |
| axis2_score | integer | 軸2スコア（実環境影響度） |
| jpcert_ipa.issued | boolean | JPCERT/CCまたはIPAが24時間窓内に注意喚起を発行したか |
| jpcert_ipa.entries | array[{title, url}] | 発行済みの場合のタイトルとURL |
| changes_24h | array[{source, date, description}] | 24時間以内の変化。dateはYYYY-MM-DD |
| overview | string | 概要（自由テキスト。AI分析での文脈理解用） |
| attack_flow | array[{step, description}] | 攻撃の流れ（stepは1始まりの整数） |
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
| report_section | string | "zero_day_special"/"main_cve"/"reference_a"/"reference_b" |

**sector_impact 制御語彙**:
"government" / "finance" / "healthcare" / "manufacturing" / "telecom" / "energy" / "education" / "retail" / "it" / "professional_services" / "defense" / "critical_infrastructure" / "other"

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
      "date": "2026-06-24",
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
  "report_section": "apt_notable"
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
  "root": {
    "evidence": "確認済みEvidenceの記述",
    "past_patterns": "類似事象での過去観測",
    "threat_intel": "現在の脅威インテル"
  },
  "estimated_part": "推定部分の記述（なければnull）",
  "early_warning_signals": "先回り監視シグナルの記述",
  "hit_criteria": "的中判定条件（測定可能な条件）",
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
| confidence_numeric | number | high=0.8 / medium=0.5 / low=0.3（AI分析での定量化用） |
| framing | string | "defensive_action" / "attacker_behavior" |
| root.evidence | string | 今日のEvidenceの記述 |
| root.past_patterns | string | 過去パターン |
| root.threat_intel | string | 現在の脅威インテル |
| estimated_part | string \| null | 推定部分（根拠十分なT1純粋継続予報はnull） |
| early_warning_signals | string | 先回り監視シグナル |
| hit_criteria | string | 的中判定条件 |
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
  "adoption_triggers": ["P", "Q"],
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
      "date": "2026-06-23",
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
  "report_section": "ai_attacks_main"
}
```

| フィールド | 型 | 値 / 説明 |
|---|---|---|
| attack_id | string | "AI-YYYY-MM-DD-NNN" 形式の一意ID |
| title | string | インシデント・研究・CVEの名称 |
| category | string | "A" / "B" / "C"（pipeline-ai-1.md のカテゴリ定義） |
| subcategory | string | "A1"〜"A6" / "B1"〜"B6" / "C1"〜"C6" |
| attacker_type | string | "criminal_org" / "nation_state" / "researcher" / "unknown" |
| adoption_triggers | array[string] | P/Q/R/S/T/U/V/W/X/Y（pipeline-ai-1.md の採用条件） |
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
      "date": "2026-06-26",
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
  ]
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
| security-report-zeroday-trends.txt | Section 2（ゼロデイ・トレンド）: zero_day_special / apt_main / apt_notable / forecasts / exclusions.apt / statistics.apt |
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
