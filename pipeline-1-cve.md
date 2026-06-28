# pipeline-1-cve.md — Step 1: CVE調査ルール

## 調査区分

Step 1 のCVE調査は以下の2トラックで行う（製品リストによる絞り込みは行わない）:

**トラック A（製品別CVE）**: 下記「採用条件 A〜H」を満たす全製品のCVEを収集し、
  Section 3【製品別CVE】として出力する。製品カテゴリは問わない。

**トラック B（トレンドCVE）**: CVSS 9.0以上・CISA KEV登録・実悪用確認・PoC公開済みなど
  高インパクトのCVEを収集し、Section 2【ゼロデイ・セキュリティトレンド】へ渡す
  （pipeline-2-trends.md が吸収する）。

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
- 以下に該当するCVEは `section_route: trends` タグを付けて pipeline-2-trends.md へ引き渡す:
  - CISA KEV 新規追加
  - CVSS 9.0以上 Critical
  - ゼロデイ・実悪用確認
  - PoC公開後 48h 以内の攻撃加速報告
  - 国内で広く使われる製品（官公庁・金融・医療等で標準採用）

---

## 調査ソース（優先順）
1. CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
2. NVD: https://nvd.nist.gov/
3. GitHub Advisory Database
4. ベンダーアドバイザリ（Fortinet / Palo Alto / Ivanti / Microsoft / Cisco / Oracle 等）
5. BleepingComputer / The Hacker News / SecurityWeek
6. PoC情報: GitHub / Exploit-DB / Packet Storm / watchTowr / ProjectDiscovery

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
- PoC公開: true / false / 未確認（true の場合URL必須）
- 優先度タグ: 必須 / 高 / 中 / 低優先度
- 関連URL（全件保持）
- 監視SPL候補: 対象製品が出力するログソース名（例: sourcetype=fortigate*, access_combined 等）と検知すべきフィールド・値のヒント（例: subtype=vpn action=tunnel-up, uri_path=*/plugins/editors/jce* 等）。Step 3でSplunk SPLクエリ生成に使用する。

## 並び順（次ステップへの引き渡し順）
1. CISA KEV / ゼロデイ
2. CVSS 9.0以上 Critical
3. PoC公開済み
4. CVSS 7.5以上 High（RCE / 認証バイパス / 権限昇格）
5. 低優先度フラグ付き（参考B昇格候補）
