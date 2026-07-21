# pipeline-2-trends.md — Step 2: 動向収集ルール

## 情報収集の原則

一次入力は `security-intel-collector/data/raw/` の当日・前日分（GitHub Actions が毎日 06:00 JST に機械収集済み）とする。
Web 検索は data/raw に無い情報を補完する場合にのみ使用する。

## このステップの区分

Step 2 は「ゼロデイ及びセキュリティのトレンド」セクションを構成する。
出力先は Section 2【ゼロデイ・セキュリティトレンド】で、以下の2つの情報源を統合する:

1. **トレンド情報**: BleepingComputer / The Hacker News 等から収集した攻撃トレンド・APT動向
2. **トラック B CVE（リスト外高インパクト）**: pipeline-1-cve.md のトラック B で
   `section_route: trends` タグが付いたCVEをここで受け取り、トレンドとして出力する

---

## トラック B CVE（リスト外製品）の扱い

pipeline-1-cve.md のトラック B から渡されたCVE（`section_route: trends` タグ付き）は、
以下のルールで Section 2 に組み込む:

- CVEセクション（製品別）には含めない
- Section 2 の中に「注目CVE（リスト外）」サブセクションを設けて掲載する
- 重みづけは CVE 重みづけモデル（軸1 × 軸2）を適用し、本編 / 参考A / 参考B へ振り分ける
- CISA KEV 登録またはゼロデイの場合はゼロデイ特報として Section 2 の先頭に置く

---

## 調査対象期間
- Step 0 で確定した24時間窓を厳守
- 窓外の情報はメインに据えない（継続フォローとして扱う）

## 必須ソース（英語）
| ソース | URL | feeds.json |
|--------|-----|-----------|
| BleepingComputer | bleepingcomputer.com | 収録済み |
| The Hacker News | thehackernews.com | 収録済み |
| SecurityWeek | securityweek.com | 収録済み |
| The Record (Recorded Future) | therecord.media | 未収録 |
| Mandiant Blog（Google Threat Intelligence） | cloud.google.com/blog/topics/threat-intelligence | 収録済み（"Google Threat Intelligence (Mandiant)"） |
| Rapid7 Blog | rapid7.com/blog | 未収録 |
| CISA Alerts | cisa.gov/news-events/alerts | 収録済み（"CISA Advisories"） |
| Unit 42（Palo Alto Networks） | unit42.paloaltonetworks.com | 収録済み |
| watchTowr Labs | labs.watchtowr.com | 収録済み |
| SANS Internet Storm Center | isc.sans.edu | 収録済み（"SANS Internet Storm Center"・スキャン/悪用の実観測データ） |

## 必須ソース（日本語）
| ソース | URL | 昇格トリガー | feeds.json |
|--------|-----|------------|-----------|
| Security NEXT | security-next.com | 記事掲載 → 参考A昇格 | 収録済み |
| JPCERT/CC 注意喚起 | jpcert.or.jp/at/ | 注意喚起発行 → 参考A昇格 | 収録済み（"JPCERT/CC"） |
| IPA 重要なセキュリティ情報 | ipa.go.jp/security/security-alert/ | 発行 → 参考A昇格 | 収録済み |
| ScanNetSecurity | scan.netsecurity.ne.jp | 国内被害報道 → 参考A昇格 | 収録済み |
| JVN（脆弱性対策情報） | jvn.jp | 発行 → 参考A昇格 | 収録済み |
| JVN iPedia（脆弱性DB） | jvndb.jvn.jp | 国内製品の登録 → 参考A昇格 | 収録済み（"JVN iPedia 新着"・詳細照会は MyJVN API: jvndb.jvn.jp/apis/myjvn/） |
| JPCERT/CC Eyes（技術ブログ） | blogs.jpcert.or.jp/ja/ | 国内標的の技術分析公開 → 参考A昇格 | 収録済み（"JPCERT/CC Eyes"） |
| 警察庁サイバー警察局 | npa.go.jp/bureau/cyber/ | 公表 → 参考A昇格 | 未収録（RSS配信なし・確認済み。Web検索で補完） |
| NISC（国家サイバー統括室） | cyber.go.jp | 公表 → 参考A昇格 | 未収録（RSS配信なし・確認済み。Web検索で補完） |

## 参考A（国内）昇格トリガー
以下のいずれか1つ以上で昇格:
- JPCERT/CC または IPA が当該CVEの注意喚起を出している
- 警察庁が国内被害を公表
- Security NEXT / ScanNetSecurity が国内被害・インシデントを報道
- 国内ベンダー（富士通・NEC・日立・NTT・トレンドマイクロ等）がアドバイザリを出している
- 国内で広く使われる製品への直接影響（国産製品 / 行政・金融で標準採用）

## 参考B（国際先行）収集基準
以下を満たす情報を国際シグナルとして収集:
- 海外で実悪用・大規模スキャン・キャンペーンが観測されている
- PoC公開後 48〜72 時間以内の攻撃加速が報告されている
- 国内でも使われる製品・OSSが対象（波及経路がある）
- 過去に同種が遅れて日本へ波及したパターンに合致

## 収集件数
- 制限なし、全件ストック
- Step 3 の重みづけで絞り込む

---

## トレンド信頼性フィルタリング（Temporal Burst Filtering）

収集した情報を Step 3 へ渡す前に以下の2段階フィルタで「単発フラッシュ」と「真のトレンド」を区別する。

### 鮮度チェック（Recency Check）
- 調査窓内（24時間以内）に**最新の記事・アドバイザリ**が存在すること
- 窓外の古い情報だけで構成される場合は「継続監視」フラグを付けて除外候補とする

### 持続性チェック（Burst Persistence Check）
- 48時間以内に**3件以上の独立したソース**（同一ベンダー系列は1件と数える）が報道・公開していること
- 3件未満の場合は「単発シグナル」フラグを付けて参考B以下に留める
- 6件以上の場合は「バースト検出閾値超過」と記録し、【24時間以内の変化】欄にその旨を1行添える

### フィルタ適用例
- FortiBleedキャンペーン: 24時間窓内に Help Net Security / BleepingComputer / Arctic Wolf / SecurityAffairs / CyberInsider 他6ソース以上 → バースト検出閾値超過・本編採用
- 単一ベンダーブログのみの報告 → 単発シグナル・参考Bまたは注目動向留め

---

## APT活動専用ソース（Step 1b が使用）

Step 1b（APT活動調査）では pipeline-1b-apt.md に定義したソースを使用する。
Step 2 は以下の追加ソースで APT関連の動向を補完する。

### APT活動の補完確認ソース
| ソース | URL | 用途 | feeds.json |
|--------|-----|------|-----------|
| Microsoft MSTIC Blog | microsoft.com/en-us/security/blog/ | 帰属・TTP | 未収録 |
| CrowdStrike Blog | crowdstrike.com/blog/ | キャンペーン観測 | 未収録 |
| Unit 42（Palo Alto） | unit42.paloaltonetworks.com | マルウェア分析 | 収録済み |
| Talos Intelligence | blog.talosintelligence.com | インフラ追跡 | 未収録 |
| Secureworks CTU | secureworks.com/research/threat-profiles | グループプロファイル | 未収録 |
| SentinelLabs | sentinelone.com/labs/ | マルウェア技術分析 | 未収録 |
| Elastic Security Labs | elastic.co/security-labs | TTP詳細 | 未収録 |
| watchTowr Labs | labs.watchtowr.com | 脆弱性リサーチ・実証 | 収録済み |
| Google Threat Intelligence（Mandiant） | cloud.google.com/blog/topics/threat-intelligence | 帰属・キャンペーン分析 | 収録済み（"Google Threat Intelligence (Mandiant)"） |
| NISC（日本） | cyber.go.jp | 公式勧告 | 未収録（RSS配信なし・確認済み。Web検索で補完） |

### APT情報の参考A昇格トリガー（CVEと同様）
以下のいずれか1つ以上で昇格:
- 警察庁 / NISC / JPCERT が特定グループの活動を公表
- 国内組織への侵害が報告・確認される
- 国内ベンダーが当該グループに関するアドバイザリを発行
