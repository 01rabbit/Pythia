# pipeline-1b-apt.md — Step 1b: APT活動調査ルール

## 概要

このステップは Step 1（CVE調査）と並行して実行する。
脆弱性単体ではなく、脅威アクターの活動・キャンペーン・TTPs を収集・評価する。
地域フォーカスなし。グローバルに重要な活動を対象とする。

---

## 調査ソース（優先順）

### 一次ソース（政府・公的機関）
| ソース | URL |
|--------|-----|
| CISA Alerts / Advisories | cisa.gov/news-events/alerts |
| CISA / FBI / NSA 合同勧告 | cisa.gov/resources-tools/resources/joint-cyber-advisories |
| NCSC（英国） | ncsc.gov.uk/section/keep-up-to-date/reports |
| ANSSI（フランス） | cert.ssi.gouv.fr |
| BSI（ドイツ） | bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage |
| NISC（日本） | nisc.go.jp/news/ |
| 警察庁サイバー警察局 | npa.go.jp/bureau/cyber/ |
| JPCERT/CC Eyes（技術ブログ） | blogs.jpcert.or.jp/ja/ |

注記:
- JPCERT/CC Eyes は日本を標的とするAPT・マルウェア・攻撃ツール・インターネット観測の
  技術分析を扱う。国内標的キャンペーンの Technique / IOC の根拠ソースとして最優先で確認する
  （security-intel-collector/feeds.json で機械収集済み・data/raw/ を一次入力とする）。

### 二次ソース（ベンダー脅威インテリジェンス）
| ソース | URL |
|--------|-----|
| Mandiant / Google Threat Intelligence | cloud.google.com/blog/topics/threat-intelligence |
| Microsoft MSTIC | microsoft.com/en-us/security/blog/ |
| CrowdStrike Blog | crowdstrike.com/blog/ |
| Unit 42（Palo Alto Networks） | unit42.paloaltonetworks.com |
| Talos Intelligence（Cisco） | blog.talosintelligence.com |
| Secureworks CTU | secureworks.com/research/threat-profiles |
| Recorded Future | recordedfuture.com/research |
| Elastic Security Labs | elastic.co/security-labs |
| SentinelLabs | sentinelone.com/labs/ |

注記:
- Europol / FBI IC3 の法執行・摘発情報は日次収集対象に含めない
- 法執行チェックは週次検証ステージ（火・木）へ移し、継続影響の確認に使用する

### IOC・マルウェア照合ソース（参照専用）

| ソース | URL | 用途 |
|--------|-----|------|
| MalwareBazaar（abuse.ch） | bazaar.abuse.ch | 報告されたマルウェアファミリー名・ハッシュの実在照合、タグ・配布情報の確認 |
| SANS Internet Storm Center | isc.sans.edu | スキャン活動・攻撃キャンペーン・悪用観測の実測データ照合 |

注記:
- これらは採用条件 T（IOC新規大量公開）・S（新規TTP）の裏取りに使用する参照ソースであり、
  ここから独自に帰属・Technique を推定しない（行動原則1・3）。
- 検体そのもののダウンロード・実行は行わない（ハッシュ・メタデータの照合のみ）。

---

## 採用条件 P〜W（期間内に1つ以上確認できること）

| 記号 | 条件 |
|------|------|
| P | 新規キャンペーン・作戦の初報 |
| Q | 政府機関による公式帰属・合同勧告の発行 |
| R | 新規マルウェアファミリーの発見・技術分析公開 |
| S | 既知グループの新規TTPまたは初観測テクニックの報告 |
| T | 確認済みIOC（IP / ドメイン / ハッシュ）の新規大量公開 |
| U | 既知グループの活動再開・休眠明けの観測報告 |
| V | 重要インフラ・政府機関・防衛産業への侵害報告 |
| W | APTが脆弱性（CVE）を武器化した新規観測報告 |

---

## 除外ルール（フラグ付け・足切り禁止）

- 期間内に P〜W が確認できない古いキャンペーン情報は除外
- 既報（reported-apts.md 掲載済み）かつ期間内に変化なし → 除外
- 以下は除外ではなく `低優先度` フラグを付けて次ステップへ渡す:
  - 単一ソースの未確認帰属レポート（確度が低い）
  - 技術詳細が不明な断片的な活動報告
  - ニッチ産業・限定的な地域のみへの影響

---

## 各APT活動エントリに付与するメタデータ

- グループ名 / 別名（APT番号・研究者ネーム）
- 国家帰属（推定含む）/ 帰属信頼度: 高 / 中 / 低
- 活動タイプ: 新規キャンペーン / TTP更新 / マルウェア発見 / 公式帰属 / IOC公開 / 活動再開
- 採用契機: P〜W の該当記号
- 期間内の変化: いつ・どのソースで・何が変化したか
- 標的セクター（複数可）
- 標的地域（複数可）
- 使用マルウェア・ツール（判明分のみ）
- 新規TTP（MITRE ATT&CK ID付き、判明分のみ）
- 確認済みIOC（IP / ドメイン / ハッシュ、判明分のみ）
- `law_enforcement_action`: 法執行・摘発イベントが週次検証で確認された場合のみ `true`
- 優先度タグ: 必須 / 高 / 中 / 低優先度
- 関連URL（全件保持）
- 監視SPL候補: 攻撃に関連するログソース名（例: sourcetype=google:gws:admin, access_combined, syslog 等）と検知すべきフィールド・値のヒント（例: name=CREATE_RULE, uri_path=*/help.php 等）。Step 3でSplunk SPLクエリ生成に使用する。

---

## campaign_id 命名規則

`活動ID / キャンペーン名`（reported-apts.md のキー列、observation の campaign_id と同一）は
以下の規則で採番する。同一キャンペーンの重複登録・表記ゆれによる二重登録を防ぐため、
**新規登録前に必ず既存キーとの類似照合を行う**。

### 形式

- グループ名が判明している場合:
  `<正規グループ名（英語表記・ハイフン/スペース除去）>-<YYYY>-<キャンペーン短名>`
  例: `Turla-2026-STOCKSTAY-EspionageCampaign`, `APT28-2026-PRISMEX-NATOLogistics`
  - 正規グループ名は原則 MITRE ATT&CK Group 名または最も広く使われる名称の英語表記1つに統一する
    （別名は「グループ名」列にまとめて記載し、campaign_id には含めない）
  - 同一グループの活動が更新された場合も campaign_id は変更しない（最終状態・最終更新日のみ更新）

- グループ帰属が不明・未確定の場合:
  `RIS-<YYYY>-<事象短名>`（Reported Incident/Signal の略。国家帰属が明示されない
  不明グループ・単発インシデントの識別に使う既存の実運用キーに合わせる）
  例: `RIS-2026-SignalBackupKey-PSA260626`
  - 「事象短名」はマルウェア名・作戦名・被害組織名など、最も特徴的な固有名詞を優先する
  - 後日帰属が判明した場合は campaign_id を正規グループ名の形式へ改称せず、
    「グループ名」列を更新し備考に帰属判明の経緯を記録する（campaign_id は不変キーとする）

### エイリアス欄

- 「グループ名」列に別名（APT番号・研究者ネーム・旧称）を `/` 区切りで併記する
  例: `Turla（Venomous Bear / Snake / IRON HUNTER / JOVIAL SERPENT / Waterbug / Krypton）`
- 別名のみでの新規 campaign_id 採番は禁止する（正規グループ名またはRIS形式を使う）

### 新規登録前の既存キー類似照合手順

1. reported-apts.md 全体を読み、以下の観点で既存キーと照合する:
   - グループ名（別名含む）が一致・類似する行がないか
   - 同一マルウェアファミリー名・C2インフラ・被害組織名が既出のキャンペーン短名に含まれていないか
   - 直近14日以内に同一グループの活動が登録されていないか（継続活動の可能性）
2. 類似・重複の疑いがある場合は新規行を追加せず、既存行の「最終状態」「最終更新日」「備考」を更新する
   （備考には新たに確認された変化点を追記し、既存記述は残す）
3. 同一事象が既に異なるキー表記で複数行に分散して登録されている疑いを検知した場合は、
   新規登録・自動統合は行わず、備考に矛盾点を記録した上で人間のレビューを仰ぐ
   （knowledge/ 同様、reported-apts.md の既存行の自動書き換え・削除は行わない）
4. 機械的な重複キー検知は `scripts/check_reported.py` が担う（本手順は目視照合の補完）

---

## 地政学先行指標（Phase 1: NK→Lazarus 先行検証）

### 採用条件
以下のいずれかが本文に含まれる記事のみ採用する。含まない純軍事ニュースは除外する。

1. 具体的なマルウェア名・C2インフラ・APT技術手法の言及
2. 暗号資産ウォレット・制裁対象機関の識別子
3. サイバー部隊名（Lazarus Group / APT38 / Kimsuky 等）

### Phase 1 優先: 北朝鮮→Lazarus連鎖シグナル

- 北朝鮮ITワーカー詐欺・採用詐欺の新規キャンペーン報道
- 暗号資産窃取（Lazarus / APT38）の新規IOC・キャンペーン報道
- UN Panel of Experts 報告書の暗号資産窃取セクション

### 収集ソース（地政学）

- Recorded Future Nation-State Reports
- UN Panel of Experts レポート
- The Record (`therecord.media`) の北朝鮮・制裁関連記事

### 予報連動ルール

`geopolitical_signal` 単体では予報を生成しない。
`geopolitical_signal` を含む observation と、同日の独立した技術的観測
（IOC公開 / CERT勧告 / 新規TTP報告）の両方が揃った場合のみ予報候補とする。

### observation への記録

- `north_korea_nexus`: Phase 1 で最優先
- `russia_nexus` / `china_nexus` / `iran_nexus`: Phase 2 以降で拡張
- `geopolitical_unattributed`: 連鎖はあるが国家帰属が明示されていない

---

## 並び順（次ステップへの引き渡し順）

1. 政府機関による公式帰属・合同勧告（Q）
2. 重要インフラ / 政府機関への侵害（V）
3. 新規マルウェア + 大規模キャンペーン（R + P）
4. 既知グループの新規TTP（S）
5. APTが CVE を武器化（W）
6. 低優先度フラグ付き
