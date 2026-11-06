# pipeline-infrastructure.md — Step 3.1: 攻撃基盤プロファイル（Section 6）の規則

## 位置づけ

Section 6 は、日次レポートに載った IoC（IP・ドメイン・URL のホスト）を**公開データベースへの
受動照会だけ**で補強し、攻撃者側プラットフォームの客観的な属性（国・保有者・ASN・開放ポート・
稼働ソフトウェアと版・脆弱性・登録情報・ホスティング先の履歴）を記録する**報告専用の文脈層**である。

**予報の入力層ではない。** 観測（`forecaster/observations/`）・ベースライン・base_rate・予報には
一切入れない（`forecast_input` は false 固定）。理由は Section 5 と同じで、補強した属性を観測母集団に
混ぜると base_rate が歪み、検証ループで予報ロジックの誤りと母集団の歪みを区別できなくなる。
観測側の `iocs`（報告された値そのもの）は従来どおりで、本層はそれを書き換えない。

**プロファイルは LLM が書かない。** `scripts/enrich_infrastructure.py` が API 応答から機械的に作り、
`scripts/validate_infrastructure_context.py` が応答の記録から要約を**再計算して照合**する。
エージェントの役割は、IoC を正確に `ioc` へ書くことと、スクリプトを実行することだけである。

## 要件との対応

| 要件（攻撃者の攻撃プラットフォームの詳細） | 本層での扱い |
|---|---|
| 国（地域） | RIPEstat の位置情報（**近似**）。攻撃者の所在を示さない旨の注意書きを付ける |
| ドメイン・URL・IPアドレス | 報告された IoC を正規化して指標にする（URL はホストを取り出す）。原文の表記も残す |
| 管理者 | ASN の保有者名（RIPEstat）・レジストラ名（RDAP）。組織名のみで、個人の連絡先は保存しない |
| 稼働サービスおよびバージョン・OS・ミドルウェア | Shodan InternetDB が保有する CPE（ソフトウェア・版）とタグ |
| オープンポート | InternetDB の開放ポート |
| 脆弱性情報 | InternetDB が関連づけた CVE。**情報源の推定であり未検証**と明記する |
| ノード種別 | InternetDB のタグを**そのまま**記録する（本層では分類しない） |
| ホスティング先の履歴 | urlscan（過去 30 日の他者のスキャン）とパッシブ DNS（Mnemonic） |

## 受動であること（最重要）

- 問い合わせ先は次の公開データベースだけである。IoC の指す IP・ドメイン自体へは接続しない。
  ドメインの名前解決もしない（再帰解決は権威サーバへ到達しうるため）。

  | ソース | 対象 | ホスト |
  |---|---|---|
  | ripestat | IP → プレフィックス・ASN・保有者・国 | stat.ripe.net |
  | internetdb | IP → ポート・CPE・タグ・脆弱性 | internetdb.shodan.io |
  | rdap | ドメイン → 登録日・レジストラ・NS | rdap.org（登録局の RDAP へリダイレクト） |
  | urlscan | ドメイン → 過去 30 日のスキャン履歴 | urlscan.io |
  | mnemonic | ドメイン → パッシブ DNS | api.mnemonic.no |

- コードが強制する: 報告された IoC と同じホストへの接続を拒否し、リダイレクト先が IoC なら拒否する。
  検証器も、照会先ホストが各ソースの既知のホストと一致すること、IoC 自身でないことを確認する
- 取得に使う User-Agent は汎用の名前にする（個人の連絡先を入れない）
- 1 回の実行で補強する指標数の上限は `config.yml` の `infrastructure.max_indicators`（既定 40）。
  超過分は `over_budget` として記録される（黙って落とさない）
- 実行環境のネットワーク許可に上記ホスト（と RDAP の登録局）が必要。許可されていなければ
  該当ソースは `failed` と記録されて続行し、検証器が警告（partial / failed）を出す

## 記録の規則

- **全照会に取得証跡**: 取得時刻（UTC）・照会先ホスト・HTTP 状態・応答本文の SHA-256・状態
  （`ok` / `no_data` / `failed`）。失敗は理由を残して続行する（フェイルソフト）
- **原文の表記を残す**: `as_reported` に報告時の文字列をそのまま残し、検証器が正規化し直して
  `indicator` に一致することを確認する（転記ミス・捏造の検出）。`198.13.53[.]226` のような無害化表記、
  `98aiblog.com（SoftEther VPN）` のような日本語の注記、`hxxps://…` は正規化して扱い、注記は `annotations` に残す
- **照会しない指標は理由付きで残す**: 非公開アドレス・予約名（`non_public`）、正規サービスや共有
  プラットフォーム（`legitimate_or_shared_platform`・`infra/policy.json`）、上限超過、有効なソースなし。
  ファイル名・パスのみなど解析できない表記は `unparsed` に理由付きで残す。**どれも黙って落とさない**
  （検証器がレポートの `ioc` から再抽出して、プロファイルと解析不能の集合が一致することを確認する）
- **公開アドレスだけをホスティング先にする**: パッシブ DNS や urlscan に現れる非公開アドレス
  （127.0.0.1 等）はホスティング先の一覧に混ぜず、`non_public_answers` として事実のまま残す。
  何を意味するか（無害化された等）は断定しない
- 応答の全文は保存しない。必要な項目だけを `extract` に残し、リストは件数上限をかける
- 個人情報は保存しない（RDAP の登録者の氏名・連絡先は捨てる）

## 解釈の限界（注意書き `caveats`）

要約・フラグ・注意書きは応答から**機械的に**導かれ、推測を含まない。次の目印が付く。

| 目印 | 意味 |
|---|---|
| `geolocation_approximate` | 国は位置情報データベースによる近似で、攻撃者の所在を示さない |
| `shared_infrastructure_not_attribution` | Cloudflare・大手クラウド等の共有基盤上。**同一基盤であることは同一運用者の根拠にならない** |
| `source_vulns_unverified` | 脆弱性の一覧は Shodan の推定で未検証 |
| `hostnames_source_asserted` | ホスト名は情報源の記述で、当該 IP の所有者を示すとは限らない |
| `urlscan_30d_window` | urlscan の履歴は過去 30 日の他者のスキャンに限られる |
| `passive_dns_partial` | パッシブ DNS は観測された範囲で網羅ではない |
| `some_sources_failed` | 取得に失敗したソースがあり情報が不足している |

加えて `newly_registered`（登録から 30 日以内）と `shared_infrastructure_providers` が付く。

**インフラの類似・共有だけで帰属しない（行動原則 3）。** 同じ ASN・同じホスティング先・同じ
レジストラであることは、同一の攻撃者であることの根拠にならない。APT エントリの帰属は
情報源が明示した場合に限る。Section 6 の属性を帰属の根拠として APT エントリや
Section 5 の `attribution` に流用してはならない。

## 禁止事項

- IoC の指す IP・ドメイン・URL への接続（HTTP・DNS 解決・ポートスキャンを含む）
- プロファイルの手書き・編集。要約を応答の記録と食い違わせる（検証器が落とす）
- プロファイルから観測・予報・Technique・`actor_group` を生成する
- インフラの類似だけで帰属する、共有基盤の IP を攻撃者固有として扱う
- 個人情報の保存、`forecaster/knowledge/` の書き換え（行動原則 5）

## 実行と検査

```bash
# Step 3.1: Section 1〜5 を含むレポート JSON が確定した後（Step 3.5 の前）
python3 scripts/enrich_infrastructure.py --date "${TODAY}"      # infrastructure_context を JSON へ注入
python3 scripts/render_infrastructure_section.py --date "${TODAY}" --append-to-full

# Step 4: コミット前
python3 scripts/validate_infrastructure_context.py --date "${TODAY}" --require
```

実行状態: `ok` / `partial`（一部の照会が失敗）/ `failed`（全件失敗）/ `no_indicators` / `disabled`。
`partial` / `failed` はコミットを止めないが、Step 5 の日次サマリーに影響とあわせて 1 行で明記する。
スキーマは `pipeline-output-schema.md`「攻撃基盤プロファイル」を参照。
テキストは JSON から `render_infrastructure_section.py` が決定論的に生成する（IP・ドメインは無害化表記）。
