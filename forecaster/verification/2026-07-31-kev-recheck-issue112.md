========================================
KEV 再照会 追跡調査メモ（Issue #112 対応）
対象: CVE-2026-16723（Fastjson 1.x RCE）／予報 fc-20260726-1
実行日: 2026-07-31
========================================

## 目的

2026-07-31 の予報精度検証で確定した fc-20260726-1（Fastjson 1.x・確度低・E1・fast_72h・
outcome=miss）について、判定時に確認された「CISA KEV カタログ本体と外部 WebSearch 二次情報の
KEV 登録有無の不一致」（Issue #112）の真因を、最新の固定一次ソース再照会によって切り分ける。

**本メモは判定の再採点を行わない**（原則D・発行済み予報の再採点禁止）。fc-20260726-1 の
`outcome` は `miss` のまま変更しない。記録先は `forecaster/verification/` 配下のみとし、
`forecaster/knowledge/` には一切書き込まない（行動原則5）。

---

## 実施した再照会（すべて観測＝事実）

### 1. CISA KEV カタログ JSON 本体（固定一次ソース）

- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- 2026-07-31 に 2 回取得。両取得のバイト列は完全一致（SHA-256 先頭16桁 `15b44d7c9c57f3d2`）。
- `catalogVersion`: **2026.07.29** ／ `dateReleased`: **2026-07-29T18:45:59.5809Z** ／ `count`: **1656**
  → 2026-07-31 検証時点から**カタログ版は進んでいない**（07-30・07-31 のリリースなし）。
- `CVE-2026-16723` のエントリ: **存在しない**（0件）。
- `vendorProject` / `product` / `vulnerabilityName` に `fastjson` または `alibaba` を含むエントリ: **0件**。

### 2. 2026-07-27 付け追加エントリの有無（仮説2の直接検証）

カタログ本体に `dateAdded == "2026-07-27"` のエントリが **2件存在する**:

| dateAdded | cveID | vendorProject | product |
|-----------|-------|---------------|---------|
| 2026-07-27 | CVE-2025-68686 | Fortinet | FortiOS |
| 2026-07-27 | CVE-2026-16812 | Arista | VeloCloud Orchestrator |

→ 07-27 の追加バッチ自体はカタログ本体（07-29 リリース版）に反映済みである。

### 3. CISA KEV CSV エクスポート（同一発行元の別表現・参考）

- URL: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
- 行数 **1655**（JSON は 1656）。差分は JSON のみに存在する `CVE-2026-20316`（dateAdded 2026-07-29）の1件。
- `CVE-2026-16723`: CSV にも **存在しない**。`CVE-2026-16812` は CSV にも `dateAdded=2026-07-27` で存在。
- → CSV エクスポートは JSON フィードに対し最新1件分だけ遅れている。**JSON フィードの方が新しい**ため、
  固定一次ソースを JSON 本体とする現行運用は妥当（この差は本件の判定には影響しない）。

### 4. NVD（KEV を `cisaExploitAdd` として取り込む独立チャネル・参考）

- API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-16723`
- `published`: 2026-07-23T09:16:26.700 ／ `lastModified`: **2026-07-23T15:01:24.377** ／ `vulnStatus`: Deferred
- `cisaExploitAdd` / `cisaActionDue` / `cisaVulnerabilityName`: **いずれも未設定（null）**
- → NVD 側にも KEV 連携の痕跡はない。加えて `lastModified` が 07-23 のまま更新されていないため、
  07-27 に KEV 追加が起きていれば通常伴うはずのレコード更新も発生していない。

### 5. 二次情報側の現在の記述

- CIRCL Vulnerability-Lookup（`https://vulnerability.circl.lu/vuln/CVE-2026-16723`）は
  **「Not yet in CISA KEV: True」** と明記している。
- 同ページは同時に、当該CVEを **KEVIntel**（CISA KEV とは別の第三者カタログ）のエントリとして
  status=Confirmed・Exploited=Yes・**first seen 2026-07-25** で掲載している。
- Tenable の CVE ページ（`https://www.tenable.com/cve/CVE-2026-16723`）には、2026-07-31 時点で
  CISA KEV 登録に関する記述は確認できなかった。

---

## 仮説の判定（Issue #112「論点」への回答）

| # | 仮説 | 判定 | 根拠 |
|---|------|------|------|
| 1 | 二次情報側の誤り（07-27 追加は事実でない） | **支持** | KEV JSON・KEV CSV・NVD の3チャネルすべてで未収録。NVD の lastModified も 07-23 のまま |
| 2 | CISA KEV カタログの反映遅延・データ欠落 | **反証** | 同じ 07-29 リリース版に 07-27 付け追加が2件反映済み。07-31 時点でも最新版は 07-29 版のままで、後続リリースによる追補も発生していない |
| 3 | 二次情報が別対象を誤って引用 | **部分的に支持（断定不可）** | 下記参照 |

### 仮説3の内訳（いずれも推測・断定しない）

- **（推測）KEVIntel と CISA KEV の混同**が最有力。「KEV」という名称を共有する非CISAカタログに
  当該CVEが Confirmed で掲載されており（first seen 2026-07-25）、これを CISA KEV への追加と
  取り違えた要約が生成された可能性がある。ただし KEVIntel の日付は 07-25 であり、二次情報が
  主張する 07-27 とは一致しないため、これを真因と確定することはできない。
- **（推測）CVE番号の取り違え**も候補。実際に 2026-07-27 に KEV 追加された `CVE-2026-16812`
  （Arista VeloCloud Orchestrator）は本件 `CVE-2026-16723` と番号帯が近く、かつ同時期に
  同一の脅威情報サイクル上で扱われていた。ただしこれを裏付ける直接証拠は得られていない。

**結論**: 仮説2（カタログ側の反映遅延・欠落）は反証された。したがって 2026-07-31 検証で
KEV カタログ JSON 本体を優先し fc-20260726-1 を **外れ** と判定した処理は妥当であり、
再照会によってその根拠が補強された。真因が仮説1・仮説3のいずれか（または両方）かは、
外部要約の生成過程を観測できないため本調査の範囲では確定できない。

---

## 記録・運用への反映

1. `forecaster/verification/2026-07.json` の `bias_analysis` に本追跡調査の結果を追記した
   （既存エントリ「固定一次ソース（CISA KEVカタログJSON）と外部WebSearch二次情報の不一致」に
   追跡完了の追記＋結果エントリの新規追加）。`entries[]` の fc-20260726-1 は
   **一切変更していない**（原則D）。
2. `pipeline-forecast-verification.md` に教訓15（E1 の固定一次ソースは CISA 発行の KEV カタログ
   本体に限り、「KEV」を名乗る第三者カタログ・アグリゲータ要約は E1 の的中根拠にならない）を
   追加提案した。これは**入口（的中根拠として何を採用してよいか）の明確化**であり、
   発行済み予報の採点尺度（出口）は変更しない。
3. カタログ反映遅延の実例としての `bias_analysis` 追記（Issue #112 の提案にあった条件付き対応）は、
   仮説2が反証されたため**実施しない**。

## 再現手順

```
curl -sS https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev.json
python3 -c "import json;d=json.load(open('kev.json'));print(d['catalogVersion'],d['dateReleased'],d['count']);print([v for v in d['vulnerabilities'] if v['cveID']=='CVE-2026-16723'])"
curl -sS 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-16723'
```

========================================
