# reported-cves.md — 既報CVEリスト

このファイルはタスク実行後に状態遷移ベースで更新されます。
同一CVEは再掲せず、`CVE-ID` をキーに `exploitation_stage`・`最終更新日`・`備考` を更新してください。

## アーカイブ規定

毎月1日、継続監視=NO かつ 最終更新日から30日超の行を `reported-cves-YYYY-MM.md`（apts/ai-attacksも同形式）へ移動する。
アーカイブ済み事案が再燃した場合は新規行として再登録し、備考にアーカイブ元を記載する。

## フォーマット

| CVE-ID | 製品名 | 初報日 | exploitation_stage | 最終更新日 | 継続監視 | 備考 |
|--------|--------|--------|--------------------|------------|----------|------|
| CVE-2026-50751 | Check Point Remote Access VPN / Mobile Access / Spark Firewall | 2026-06-15 | active_exploitation | 2026-06-15 | YES | KEV登録・JPCERT+IPA注意喚起・Qilinランサムウェア悪用確認・本編採用 |
| CVE-2026-10520 | Ivanti Sentry | 2026-06-15 | active_exploitation | 2026-06-15 | YES | CVSS 10.0・KEV登録・CISA BOD 26-04期限到来・PoC公開・バックドア確認・本編採用 |
| CVE-2026-42897 | Microsoft Exchange Server 2016/2019/SE | 2026-06-15 | none | 2026-06-15 | YES | CVSS 8.1・JPCERT注意喚起・June Patch Tuesday修正済み・参考A採用 |
| CVE-2026-54420 | LiteSpeed cPanel Plugin (2.4.8未満) | 2026-06-17 | kev_listed | 2026-06-17 | YES | CVSS 8.5・KEV登録・Security NEXT国内報道・共有ホスティングroot権限昇格・参考A採用 |
| CVE-2026-20262 | Cisco Catalyst SD-WAN Manager (複数バージョン) | 2026-06-17 | active_exploitation | 2026-06-17 | YES | CVSS 6.5・KEV登録・Security NEXT国内報道・実悪用確認（限定的）・参考A採用 |
| CVE-2026-53435 | Jenkins (2.567以前 / LTS 2.555.2以前) | 2026-06-17 | active_exploitation | 2026-06-17 | YES | CVSS 9.0・実悪用確認（ハニーポット）・デシリアライゼーションRCE・参考B採用 |
| CVE-2026-39808 | Fortinet FortiSandbox (4.4.x / 5.0.x) | 2026-06-17 | active_exploitation | 2026-06-17 | YES | 未認証OSコマンドインジェクションRCE・PoC公開済み・6/16実悪用観測・参考B採用 |
| CVE-2026-39813 | Fortinet FortiSandbox (4.4.x / 5.0.x) | 2026-06-17 | active_exploitation | 2026-06-17 | YES | パストラバーサル・認証バイパス・6/16実悪用観測・参考B採用 |
| CVE-2026-47281 | Microsoft Defender (Windows 10/11 全バージョン) | 2026-06-16 | active_exploitation | 2026-06-16 | YES | ゼロデイ未パッチ・CVSS 9.6・PoC公開・実悪用確認・RoguePlanet・本編採用 |
| CVE-2026-35273 | Oracle PeopleSoft Enterprise PeopleTools 8.61/8.62 | 2026-06-16 | active_exploitation | 2026-06-16 | YES | CVSS 9.8・KEV登録・BOD 26-04期限6/15到来・ShinyHunters実悪用・ランサムウェア展開・Security NEXT国内報道・本編採用 |
| CVE-2026-5027 | Langflow AIアプリ開発プラットフォーム (1.8.x以前) | 2026-06-18 | active_exploitation | 2026-06-18 | YES | CVSS 8.8・VulnCheck KEV登録・実悪用確認・PoC公開・Security NEXT国内報道・本編採用 |
| CVE-2026-50656 | Microsoft Defender (Windows 10/11 全バージョン・完全パッチ適用環境含む) | 2026-06-18 | poc_public | 2026-06-18 | YES | CVSS 7.8・ゼロデイ（パッチ未提供）・PoC公開（Nightmare Eclipse）・RoguePlanet CVE-2026-47281修正バイパス・参考B採用 |
| CVE-2026-24858 | Fortinet FortiCloud SSO (FortiGate 全バージョン) | 2026-06-19 | none | 2026-06-19 | YES | CVSS 9.8・SAMLバイパス・FortiBleed大規模クレデンシャル流出（73,932台）・June 18公開・本編採用 |
| CVE-2026-48907 | Widget Factory Joomla Content Editor (JCE) 1.0.0〜2.9.99.4 | 2026-06-19 | kev_listed | 2026-06-19 | YES | CVSS 10.0・KEV登録（2026-06-16）・BOD 26-04期限2026-06-19到来・未認証PHPコード実行・参考B採用 |
| CVE-2026-20253 | Splunk Enterprise 10.2.0〜10.2.3 / 10.0.0〜10.0.6 | 2026-06-21 | active_exploitation | 2026-06-21 | YES | CVSS 9.8・KEV登録（2026-06-18）・FCEB期限2026-06-21・未認証RCE（PostgreSQLサイドカー）・実悪用確認・Security NEXT 2026-06-19報道・本編採用 |
| CVE-2026-42530 | NGINX Open Source 1.31.0〜1.31.1 | 2026-06-21 | none | 2026-06-21 | YES | CVSSv4.0 9.2・HTTP/3 Use-After-Free・未認証RCE条件付き・Security NEXT 2026-06-18報道・参考A採用 |
| CVE-2026-42055 | NGINX Open Source 1.13.10〜1.31.1 / NGINX Plus R30〜R34 | 2026-06-21 | none | 2026-06-21 | YES | CVSSv4.0 9.2・proxy/grpcモジュールヒープバッファオーバーフロー・未認証RCE条件付き・Security NEXT 2026-06-18報道・参考A採用 |
| CVE-2026-20181 | Cisco Identity Services Engine (ISE / ISE-PIC) 3.3 p11未満 / 3.4 p6未満 / 3.5 | 2026-06-22 | none | 2026-06-22 | YES | CVSS 9.1・認証済みRCE・CVE-2026-20190との二段階チェーンで実質未認証RCE・Security NEXT 2026-06-18報道・参考A採用 |
| CVE-2026-20190 | Cisco Identity Services Engine (ISE / ISE-PIC) 3.3 p11未満 / 3.4 p6未満 / 3.5 | 2026-06-22 | none | 2026-06-22 | YES | CVSS 7.1・未認証XXE情報漏洩・CVE-2026-20181への連鎖起点・Security NEXT 2026-06-18報道・参考Aに統合採用 |
| CVE-2026-28318 | SolarWinds Serv-U 15.5.4 Hotfix 1未満 | 2026-06-22 | kev_listed | 2026-06-22 | YES | CVSS 7.5・KEV登録（2026-06-05）・FCEB期限2026-06-19到来・未認証DoS（サービスクラッシュ）・参考B採用 |
| CVE-2026-11645 | Google Chrome / Chromium V8（149.0.7827.102未満） | 2026-06-23 | active_exploitation | 2026-06-23 | YES | CVSS 8.8・KEV登録（2026-06-09）・FCEB期限2026-06-23到来・実悪用確認・本編採用 |
| CVE-2026-20245 | Cisco Catalyst SD-WAN Manager（複数バージョン） | 2026-06-23 | active_exploitation | 2026-06-23 | YES | CVSS 7.8・KEV登録（2026-06-09）・FCEB期限2026-06-23到来・実悪用確認（ゼロデイ確認後パッチ提供）・参考B採用 |
| CVE-2026-7473 | Arista Extensible Operating System（EOS） | 2026-06-23 | active_exploitation | 2026-06-23 | YES | CVSS 6.9・KEV登録・FCEB期限2026-06-23到来・実悪用確認・低優先度フラグ・参考B採用 |
| CVE-2026-4020 | WordPress Gravity SMTPプラグイン（2.1.5未満） | 2026-06-23 | active_exploitation | 2026-06-23 | YES | CVSS 5.3・KEV未登録・17M超exploit attempt・API鍵窃取・低優先度フラグ・参考B採用 |
| CVE-2026-8461 | FFmpeg 8.1.2未満（Jellyfin / Nextcloud / Kodi / Emby / OBS Studio等多数） | 2026-06-23 | poc_public | 2026-06-23 | YES | CVSS 8.8・MagicYUVデコーダ ヒープ境界外書き込み・JFrog RCE実証済み（50KB AVI/MKV）・KEV未登録・参考B採用 |
| CVE-2026-47729 | Squid Proxy 全バージョン（デフォルト設定） | 2026-06-23 | none | 2026-06-23 | YES | CVSS未公開・Heartbleed類似ヒープover-read・29年物FTPゲートウェイバグ・パッチ未提供（7.7予定）・低優先度フラグ・参考B採用 |
| CVE-2026-10735 | ShapedPlugin WordPress Proプラグイン（Product Slider Pro 3.5.4未満 / Real Testimonials Pro 3.2.5 / Smart Post Show Pro 4.0.2未満） | 2026-06-23 | none | 2026-06-23 | YES | CVSS 9.8・サプライチェーン攻撃・バックドア埋込・webshell・TOTP窃取・C2 194.76.217.28・参考B採用 |
| CVE-2026-49777 | ShapedPlugin Product Slider Pro for WooCommerce（3.5.4未満） | 2026-06-23 | none | 2026-06-23 | YES | CVSS 10.0・CVE-2026-10735と同一インシデント・任意ファイル書き込み・参考B統合採用 |
| CVE-2026-7273 | Zyxel GS1900シリーズ スイッチ（2.90.x.1C0以前） | 2026-06-23 | none | 2026-06-23 | YES | CVSS 8.8・LAN-based未認証OSコマンドインジェクション・スタックバッファオーバーフロー・Security NEXT国内報道・参考A採用 |
| CVE-2026-0533 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | none | 2026-06-23 | YES | Stored XSS→コード実行・ユーザー操作要・デザイン名ペイロード・Security NEXT国内報道・参考A採用 |
| CVE-2026-0534 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | none | 2026-06-23 | YES | Stored XSS→コード実行・部品属性ペイロード・Security NEXT国内報道・参考A統合採用 |
| CVE-2026-0535 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | none | 2026-06-23 | YES | Stored XSS→コード実行・コンポーネント説明ペイロード・Security NEXT国内報道・参考A統合採用 |
| CVE-2026-45585 | Microsoft Windows BitLocker（Windows 11 24H2/25H2/26H1・Server 2022/2025） | 2026-06-24 | poc_public | 2026-06-24 | YES | CVSS 6.8・ゼロデイ（パッチ2026-06-10提供済み）・PoC公開（Nightmare Eclipse/YellowKey）・BitLockerバイパス・ゼロデイ特報採用 |
| CVE-2026-34908 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | kev_listed | 2026-06-24 | YES | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・未認証アクセス制御バイパス・RCEチェーン起点・Security NEXT国内報道・本編採用 |
| CVE-2026-34909 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | kev_listed | 2026-06-24 | YES | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・パストラバーサル・RCEチェーン構成・本編採用 |
| CVE-2026-34910 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | kev_listed | 2026-06-24 | YES | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・コマンドインジェクション・root RCE・本編採用 |
| CVE-2025-67038 | Lantronix EDS5000 2.1.0.0R3以前 | 2026-06-24 | kev_listed | 2026-06-24 | YES | CVSS 9.8・KEV登録（2026-06-23）・FCEB期限2026-06-26・未認証root権限コマンドインジェクション・Security NEXT国内報道・本編採用 |
| CVE-2026-20230 | Cisco Unified Communications Manager / Unified CM SME 14.x/15.x | 2026-06-24 | active_exploitation | 2026-07-03 | YES | CVSS 8.6・Cisco Critical SIR・PoC公開（SSD 2026-06-24）・実悪用確認（Tor経由ウェブシェル展開 2026-06-22〜24）・KEV未登録・本編採用 / CVSS 8.6・KEV登録（2026-06-25、既報2026-06-24からKEV未登録→登録のステータス変化）・FCEB期限2026-06-28・パッチ後Webシェル残存確認（/platform-services/axis2-web/）・本編再採用 / Cisco公式が実悪用を確認（BleepingComputer 2026-07-01）・Defused観測で2026-06-22頃からfile://ペイロード攻撃・Shadowserverがアジア/北米中心に露出インスタンス200台超確認・EPSSパーセンタイル98.5・攻撃予報1（T1/E2/fast_72h/確度中・2026-07-03分バックフィル・期限2026-07-06）起点・本編再採用（2026-07-03分バックフィルレポート） |
| CVE-2026-8732 | WP Maps Pro WordPress プラグイン 6.1.0以前 | 2026-06-24 | active_exploitation | 2026-06-24 | YES | CVSS 9.8・実悪用確認（Wordfence 24h 2,858件ブロック）・未認証管理者アカウント作成・本編採用 |
| CVE-2026-11374 | ManageEngine ADSelfService Plus 6528以前 / RecoveryManager Plus 6320以前 / M365 Manager Plus 4816以前 / ADAudit Plus 8702以前 | 2026-06-24 | none | 2026-06-24 | YES | CVSS 9.0・SSO認証チケット予測によるアカウント乗っ取り・Security NEXT国内報道・参考A採用 |
| CVE-2026-24155 | NVIDIA NeMo AIフレームワーク 2.7.2以前 | 2026-06-24 | none | 2026-06-24 | YES | CVSS 7.8・コードインジェクション・Security NEXT国内報道・参考A採用 |
| CVE-2026-24252 | NVIDIA NeMo AIフレームワーク 2.7.2以前（Linux） | 2026-06-24 | none | 2026-06-24 | YES | CVSS 7.8・OSコマンドインジェクション・Security NEXT国内報道・参考A統合採用 |
| CVE-2026-24228 | NVIDIA NeMo AIフレームワーク 2.7.2以前（Linux） | 2026-06-24 | none | 2026-06-24 | YES | CVSS 7.8・安全でないデシリアライゼーション・Security NEXT国内報道・参考A統合採用 |
| CVE-2026-41089 | Windows Server 2012 R2〜2025（Netlogonサービス） | 2026-06-24 | active_exploitation | 2026-06-24 | YES | CVSS 9.8・未認証0-click RCE・ドメインコントローラ完全掌握・ベルギーCCB実悪用確認（2026-05-29）・KEV未登録・参考B採用 |
| CVE-2026-49975 | Apache HTTP Server 2.4.17〜2.4.67（mod_http2） | 2026-06-24 | poc_public | 2026-06-24 | YES | CVSS 8.7(v4)/7.5(v3.1)・HTTP/2 Bomb DoS・PoC公開・4000倍増幅・参考B採用 |
| CVE-2026-44963 | Veeam Backup & Replication 12.3.2.4465以前（バージョン12系） | 2026-06-25 | poc_public | 2026-06-25 | YES | CVSS 9.4・PoC公開（GitHub 2026-06-10）・BleepingComputer/THN 2026-06-24〜25報道・ドメインユーザー認証RCE・パッチ提供済み（12.3.2.4854）・参考B採用 |
| CVE-2026-13028 | Google Chrome 149.0.7827.196未満（WebGL） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google Critical・WebGL Use-After-Free・サンドボックス脱出の起点となりうる構造・Security NEXT 2026-06-25報道（記事186374）・PoC未公開・参考A採用 |
| CVE-2026-13032 | Google Chrome 149.0.7827.196未満（WebGL） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google Critical・WebGL Use-After-Free・Google内部発見・CVE-2026-13028とチェーン悪用リスク・Security NEXT 2026-06-25報道・PoC未公開・参考A採用 |
| CVE-2026-13033 | Google Chrome 149.0.7827.196未満（Blink InterestGroups） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google Critical・Protected Audience API境界外読み取り・Security NEXT 2026-06-25報道・PoC未公開・参考A採用 |
| CVE-2026-13038 | Google Chrome 149.0.7827.196未満（Autofill） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google Critical・Autofill関連・詳細未公表・認証情報窃取チェーン悪用リスク・Security NEXT 2026-06-25報道・PoC未公開・参考A採用 |
| CVE-2026-13281 | Google Chrome 149.0.7827.201未満（Mojo） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google High・Mojo整数オーバーフロー・CWE-190・レンダラ侵害後のサンドボックス脱出起点・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用 |
| CVE-2026-13282 | Google Chrome 149.0.7827.201未満（Payments） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google High・Payments Use-After-Free・CWE-416・決済情報窃取リスク・Googleが2026-05-28発見・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用 |
| CVE-2026-13283 | Google Chrome 149.0.7827.201未満（AdFilter） | 2026-06-26 | poc_public | 2026-06-26 | YES | Google High・AdFilter Use-After-Free・CWE-416・Googleが2026-06-11発見・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用 |
| CVE-2026-12569 | PTC Windchill PDMlink / FlexPLM 11.0 M030未満 | 2026-06-26 | active_exploitation | 2026-06-27 | YES | CVSS 9.8・CWE-502デシリアライゼーションRCE・KEV 2026-06-25登録・FCEB期限2026-06-28・JSP Webシェル実悪用継続・C2 IP 5.180.41.35・参考B採用 / CVSS 9.3・KEV登録（2026-06-25）・FCEB期限2026-06-28・JSP Webシェル展開継続（PTC公式確認）・実悪用確認・バースト閾値超過6ソース・本編採用 |
| CVE-2026-46331 | Linux kernel net/sched/act_pedit（v5.18〜v7.1-rc6） | 2026-06-27 | poc_public | 2026-06-27 | YES | High相当・PoC公開（packet_edit_meme）・RHEL 8/9/10・Debian 13での特権昇格確認・pedit COW・Kubernetes環境エスケープリスク・参考B採用 |
| CVE-2026-13136 | Synology MailPlus Server 4.0.1-31663未満 | 2026-06-27 | none | 2026-06-27 | YES | Critical相当・不正認証チェック（任意ファイルR/W・DoS）・Synology SA-26:11・Help Net Security 2026-06-26報道・参考B採用（CVE-2026-13135・CVE-2025-15660と同一Synology SA-26:11内の複合脆弱性） |
| CVE-2026-13135 | Synology MailPlus Server 4.0.1-31663未満 | 2026-06-27 | none | 2026-06-27 | YES | Critical相当・通信チャネル不適切制限（内部サービスアクセス）・Synology SA-26:11・Help Net Security 2026-06-26報道・参考B採用（CVE-2026-13136・CVE-2025-15660と同一Synology SA-26:11内の複合脆弱性） |
| CVE-2025-15660 | Synology MailPlus Server 4.0.1-31663未満 | 2026-06-27 | none | 2026-06-27 | YES | Critical相当・弱PRNG（任意ファイルアクセス・DoS）・Synology SA-26:11・Help Net Security 2026-06-26報道・参考B採用（CVE-2026-13136・CVE-2026-13135と同一Synology SA-26:11内の複合脆弱性） |
| CVE-2026-43503 | Linux kernel (net/sched DirtyClone) < 7.1-rc5 | 2026-06-28 | poc_public | 2026-06-28 | YES | CVSS 8.8・CWE-362競合状態LPE・JFrog PoC公開2026-06-25・THN/BleepingComputer 2026-06-27報道・Kubernetes環境コンテナエスケープリスク・参考B採用 |
| CVE-2026-48558 | SimpleHelp Remote Support Software v5.5.15 以下（OIDC 有効構成） | 2026-06-29 | active_exploitation | 2026-07-01 | YES | CVSS 10.0・CWE-287 OIDC認証バイパス・PoC公開（Horizon3.ai）・Djinn Stealer展開・AI開発者認証情報/MCPコンフィグ/SSH/クラウド認証情報窃取・14,000台超露出・v5.5.16パッチリリース済み・ゼロデイ特報採用・Section 4 SOC推奨情報(高)採用／CISA KEV登録済み（2026-06-29）・FCEB期限2026-07-02・Blackpoint CyberがTaskWeaver（jquery.js偽装Node.jsローダー）経由でDjinn Stealerを展開する二段階攻撃チェーンの詳細を新たに確認・AI開発ツール認証情報を標的・参考B採用（既報2026-06-30本編→本日は継続観測のため参考Bへ） |
| CVE-2026-46817 | Oracle E-Business Suite (EBS) Payments / File Transmission 12.2.3〜12.2.15 | 2026-06-29 | active_exploitation | 2026-07-01 | YES | CVSS 9.8・2026年5月CSPU修正済み・2026-06-27〜28から実悪用確認・C2 IP 45.84.137.125・財務/ERP標的・PoC未公開・KEV未登録・参考B採用（注目CVE）・Section 4 SOC推奨情報(高)採用／PoC公開前から実悪用継続（Defused Cyberハニーポット2026-06-27初観測）・Shadowserverが約950台のインターネット公開インスタンスを確認・参考B採用（既報2026-06-30ゼロデイ特報→本日は新規進展なく参考Bへ） |
| CVE-2026-44024 | Fluentd v1.17.0 以下 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 9.8・CWE-94コード注入RCE・v1.17.1パッチリリース済み・悪用確認なし・PoC未公開・参考A採用 |
| CVE-2026-55200 | libssh2 1.11.0 以下 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 9.8・CWE-121スタックバッファオーバーフロー・1.11.1パッチリリース済み・悪用確認なし・参考A採用 |
| CVE-2026-5173 | GitLab CE/EE 17.8.0〜17.11.3 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 8.5・CWE-290認証バイパス・17.11.4/17.12.2パッチリリース済み・悪用確認なし・参考A採用 |
| CVE-2026-12244 | NSD (Name Server Daemon) 4.9.3 以下 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 8.8・CWE-119バッファエラー・4.9.4パッチリリース済み・悪用確認なし・参考A採用（CVE-2026-12245・CVE-2026-12246と同一NSDアドバイザリ内の複合脆弱性） |
| CVE-2026-12245 | NSD (Name Server Daemon) 4.9.3 以下 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 8.8・CWE-119バッファエラー・4.9.4パッチリリース済み・悪用確認なし・参考A採用（CVE-2026-12244・CVE-2026-12246と同一NSDアドバイザリ内の複合脆弱性） |
| CVE-2026-12246 | NSD (Name Server Daemon) 4.9.3 以下 | 2026-06-29 | none | 2026-06-29 | YES | CVSS 8.8・CWE-119バッファエラー・4.9.4パッチリリース済み・悪用確認なし・参考A採用（CVE-2026-12244・CVE-2026-12245と同一NSDアドバイザリ内の複合脆弱性） |
| CVE-2026-8037 | Progress Kemp LoadMaster / ECS Connection Manager / Object Scale Connection Manager / MOVEit WAF | 2026-06-30 | poc_public | 2026-07-01 | YES | CVSS 9.8・CWE-78未認証root権限OSコマンドインジェクション・watchTowr Labs詳細エクスプロイトチェーン公開（2026-06-29）・同日からeSentireが実悪用試行を観測（送信元IP 3件・試行は失敗）・2026-06-04パッチ提供済み・参考B採用・攻撃予報1（T1/E1/fast_72h/確度中）起点 |
| CVE-2026-33825 | Microsoft Defender Antimalware Platform（BlueHammer） | 2026-06-30 | active_exploitation | 2026-07-01 | YES | CVSS 7.8・KEV登録済み（2026年4月22日）・2026-06-30にCISAがランサムウェアキャンペーン悪用フラグをUnknown→Knownへ更新（M4観測）・2026年4月パッチ提供済み・本日本編採用 |
| CVE-2026-56137 | RPGツクールMV（1.6.3以前） / RPGツクールMZ（1.10.0以前） | 2026-07-01 | none | 2026-07-01 | YES | CVSS 7.8/CVSSv4 8.4・JVN新規公開（JVNDB-2026-000093）・セーブデータ読み込み時OSコマンドインジェクション・パッチ未提供（開発元EOL対応中）・参考A採用 |
| CVE-2026-56808 | AVTECH DGM3103SCT（3MP H.265 IRネットワークカメラ、ファームウェア3.2.5.4以前） | 2026-07-01 | none | 2026-07-01 | YES | CVSS 7.2/CVSSv4 8.6・JVN新規公開（JVN#28979424）・認証済み管理者権限が前提のOSコマンドインジェクション・パッチ提供済み・参考A採用 |
| CVE-2026-8451 | NetScaler ADC / NetScaler Gateway（14.1-72.61未満 / 13.1-63.18未満、FIPS/NDcPP含む） | 2026-07-02 | active_exploitation | 2026-07-07 | YES | CVSSv4 8.8/CVSSv3 7.5・watchTowr Labs発見「CitrixBleed To Infinity And Beyond」・SAML IDP設定時の境界外メモリ読み取り（NSC_TASSクッキー漏洩）・KEV未登録・実悪用未確認・Security NEXT国内報道・本編採用 / Lupovisが開示から24時間以内（2026-06-30〜07-01）に完全なエクスプロイトペイロードを観測・実悪用確認・KEV未登録・本編再採用（2026-07-03分バックフィルレポート） / Dark Reading 2026-07-06「CitrixBleed-ing Again?」は既報内容の再掲・新規事実なしのため既報・変化なしとして除外（2026-07-07分レポート） |
| CVE-2026-55957 | Apache Tomcat（JVNVU#93304382・複数バージョン系列） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 7.3・JNDIRealm+GSSAPIバインド認証時の認証バイパス（Missing Critical Step in Authentication）・JVN発行・実悪用未確認・参考A採用 |
| CVE-2026-55956 | Apache Tomcat（JVNVU#93304382・複数バージョン系列） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 6.5・デフォルトサーブレットのメソッド制約無視（Improper Authorization）・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-55955 | Apache Tomcat（JVNVU#93304382・複数バージョン系列） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 6.5・クラスタEncryptInterceptorリプレイ攻撃（Improper Authentication）・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-55276 | Apache Tomcat（JVNVU#93304382・複数バージョン系列） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 9.1・実効web.xmlログ出力での認可制約欠落（Always-Incorrect Control Flow）・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-53434 | Apache Tomcat（JVNVU#93304382・FFMベースコネクタ使用時） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 9.1・CRLエラー条件検知後の対処不備（Detection of Error Condition Without Action）・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-53404 | Apache Tomcat（JVNVU#93304382・複数バージョン系列） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 7.3・RewriteValve OR条件チェーンの制御フロー不備・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-50229 | Apache Tomcat（JVNVU#93304382・number guessサンプルアプリ使用時） | 2026-07-02 | none | 2026-07-02 | YES | CVSS 6.1・同梱サンプルアプリの反射型XSS・JVN発行・参考A採用（同一JVNVU#93304382内の複合脆弱性） |
| CVE-2026-50548 | Cursor IDE（AIコードエディタ、3.0未満） | 2026-07-01 | poc_public | 2026-07-02 | YES | CVSSv3.1 9.8/CVSSv4 9.3・Cato AI Labs発見「DuneSlide」・ゼロクリック・プロンプトインジェクション経由サンドボックス回避RCE・run_terminal_cmd working_directory検証不備・修正済み(3.0)・実悪用未確認・CVEパイプラインではlow_score（国内ソース未確認）だがAI攻撃本編で採用 |
| CVE-2026-50549 | Cursor IDE（AIコードエディタ、3.0未満） | 2026-07-01 | poc_public | 2026-07-02 | YES | CVE-2026-50548と同一disclosure（DuneSlide）・シンボリックリンク解決チェックのフォールバック不備・修正済み(3.0)・実悪用未確認・CVEパイプラインではlow_scoreだがAI攻撃本編で採用 |
| CVE-2026-6682 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6683 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6684 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6685 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6686 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6687 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-6688 | FatFs（ChaN製 汎用FATファイルシステムライブラリ。ESP-IDF/STM32Cube/Zephyr RTOS/MicroPython/ArduPilot/RT-Thread/Mbed/TizenRT/SWUpdate等に組み込み） | 2026-07-04 | poc_public | 2026-07-04 | YES | ゼロデイ特報採用・パッチ未提供（開発元EOL/未応答対応中）・PoC公開済み(GitHub)・実悪用未確認・FatFs OSSエコシステム横断事案 |
| CVE-2026-13368 | WatchGuard Firebox（Fireware OS） | 2026-07-04 | none | 2026-07-04 | YES | CVSSv4 9.2・WatchGuard Fireware OS外部LDAP認証構成VPN use-after-free・Security NEXT国内報道・参考A採用 |
| CVE-2026-44946 | SUSE Rancher（コンテナ管理ツール） | 2026-07-04 | none | 2026-07-04 | YES | CVSSv4 9.5(一部ソースのみ・NVD未確認)・SAMLアサーション再生（事前認証Cookie窃取前提）・Rancher 2.14.3で修正・参考A採用 |
| CVE-2026-44947 | SUSE Rancher（コンテナ管理ツール） | 2026-07-04 | none | 2026-07-04 | YES | PSAクリーンアップ権限昇格・Rancher 2.14.3で修正・参考A採用（CVE-2026-44946と同一アドバイザリ内の複合脆弱性） |
| CVE-2026-44948 | SUSE Rancher（コンテナ管理ツール） | 2026-07-04 | none | 2026-07-04 | YES | Fleet ImageScanパストラバーサル/DoS・Rancher 2.14.3で修正・参考A採用（同一アドバイザリ内の複合脆弱性） |
| CVE-2026-44949 | SUSE Rancher（コンテナ管理ツール） | 2026-07-04 | none | 2026-07-04 | YES | Fleet workspace RBAC不備・Rancher 2.14.3で修正・参考A採用（同一アドバイザリ内の複合脆弱性） |
| CVE-2026-24260 | NVIDIA Container Toolkit / GPU Operator | 2026-07-04 | none | 2026-07-04 | YES | CVSS8.5・NVIDIA Container Toolkit/GPU Operator TOCTOU競合状態・権限昇格リスク・Security NEXT国内報道・参考A採用 |
| CVE-2026-33612 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | CVSS7.5・PowerDNS Recursor ZoneToCacheキャッシュポイズニング・ScanNetSecurity国内報道・参考A採用 |
| CVE-2026-40012 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・ScanNetSecurity国内報道・参考A採用（CVE-2026-33612と同一アドバイザリ） |
| CVE-2026-42005 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-42387 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-42388 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-42389 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-42390 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-52690 | PowerDNS Recursor | 2026-07-04 | none | 2026-07-04 | YES | PowerDNS Recursor複合脆弱性・参考A採用（同一アドバイザリ） |
| CVE-2026-56809 | Ricoh Web Image Monitor（複数のレーザープリンタ・複合機/MFP搭載） | 2026-07-04 | none | 2026-07-04 | YES | CVSS6.1・Ricoh Web Image Monitor反射型XSS（複数プリンタ/MFP）・ユーザー操作前提・ScanNetSecurity国内報道・参考A採用 |
| CVE-2026-50043 | セイコーソリューションズ SkyBridge MB-A100 / MB-A110（IoT向けルータ） | 2026-07-04 | none | 2026-07-04 | YES | CVSS7.2/CVSSv4 8.6・セイコーソリューションズSkyBridge OSコマンドインジェクション・EOL製品でパッチ提供予定なし・ScanNetSecurity/Security NEXT国内報道・参考A採用 |
| CVE-2026-12166 | Little Orbit GamersFirst Anti-Cheat（GFAC_Sys_x64.sysドライバ） | 2026-07-04 | none | 2026-07-04 | YES | Little Orbit GamersFirst Anti-CheatドライバNULLポインタ参照DoS・ローカル限定・JVN発行・参考A採用 |
| CVE-2026-12167 | Little Orbit GamersFirst Anti-Cheat（GFAC_Sys_x64.sysドライバ） | 2026-07-04 | none | 2026-07-04 | YES | GFACドライバminifilter通信ポートセキュリティ記述子不備・ローカル限定・JVN発行・参考A採用（同一JVN内複合脆弱性） |
| CVE-2026-12168 | Little Orbit GamersFirst Anti-Cheat（GFAC_Sys_x64.sysドライバ） | 2026-07-04 | none | 2026-07-04 | YES | GFACドライバ任意カーネルメモリ書き込みSYSTEM権限昇格・ローカル限定・JVN発行・参考A採用（同一JVN内複合脆弱性） |
| CVE-2026-14355 | PHP | 2026-07-04 | none | 2026-07-04 | YES | PHP OpenSSL AES-WRAP-PADメモリ破損（openssl_encrypt）・Security NEXT国内報道・参考A採用 |
| CVE-2025-3248 | Langflow | 2025年5月（既存CVE） | active_exploitation | 2026-07-05 | YES | CVSS9.8・CWE-306未認証コード実行・KEV登録済み（2025-05-05）・v1.3.0で修正済み・自律型AIエージェント駆動ランサムウェア「JadePuffer」（Sysdig報告）の侵入起点として新規実悪用確認・EPSSパーセンタイル99.98（2026-07-04時点）・参考B採用 |
| CVE-2026-12184 | PHP | 2026-07-04 | none | 2026-07-04 | YES | PHP file_get_contents()プロキシ経由DoS（8.3.32のみ）・Security NEXT国内報道・参考A採用（CVE-2026-14355と同一更新内複合脆弱性） |
| CVE-2026-45659 | Microsoft SharePoint Server（Subscription Edition / 2019 / Enterprise Server 2016） | 2026-07-03 | active_exploitation | 2026-07-03 | YES | CVSS8.8・KEV登録（2026-07-01）・FCEB期限2026-07-04・デシリアライゼーションRCE（Site Member最小権限で悪用可）・Shadowserver露出サーバ1万台超確認・Security NEXT国内報道・本編採用（2026-07-03分バックフィルレポート） |
| CVE-2025-5777 | Citrix NetScaler ADC / NetScaler Gateway（Citrix Bleed 2） | 2025年（既存CVE） | active_exploitation | 2026-07-03 | YES | CVSS9.3・KEV登録済み（2025-07-10）・EPSSパーセンタイル99.96・Anubisランサムウェアアフィリエイトによる新規悪用確認・正規RMMツール悪用・参考B採用（2026-07-03分バックフィルレポート） |
| CVE-2026-10109 | IBM Db2 Server（V11.5.0〜11.5.9 / V12.1.0〜12.1.4） | 2026-07-03 | none | 2026-07-03 | YES | CVSS9.8・CWE-94未認証事前認証コードインジェクション・正式GA修正未提供（Special Build暫定修正のみ）・実悪用未確認・Security NEXT国内報道・参考A採用（2026-07-03分バックフィルレポート） |
| CVE-2026-43724 | macOS Tahoe（26.5.2未満・37件の脆弱性を含む更新の代表CVE） | 2026-07-03 | none | 2026-07-03 | YES | カーネルクラッシュ/メモリ書き込み不具合・AI支援エクスプロイト開発懸念による早期リリース・実悪用未確認・Security NEXT国内報道・参考A採用（他36件は同一更新内の複合脆弱性、2026-07-03分バックフィルレポート） |
| CVE-2026-14241 | Mozilla Firefox（152.0.3未満） | 2026-07-03 | none | 2026-07-03 | YES | Mozilla severity: High・メモリ安全性脆弱性（MFSA 2026-62）・実悪用未確認・Security NEXT国内報道・参考A採用（2026-07-03分バックフィルレポート） |
| CVE-2026-20213 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性（DoS類）・回避策なし・Security NEXT国内報道・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性、2026-07-03分バックフィルレポート） |
| CVE-2026-20214 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-20215 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-20216 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-20217 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-20243 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-20244 | ClamAV（Cisco Secure Endpoint Connector同梱） | 2026-07-03 | none | 2026-07-03 | YES | CVSS7.5・ファイルフォーマットパーサー脆弱性・参考A採用（同一Ciscoアドバイザリ内の複合脆弱性） |
| CVE-2026-48276 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS10.0・事前認証RCE・Adobe Priority Rating 1・watchTowr技術解析・実悪用未確認・参考B採用（APSB26-68・11件の複合脆弱性、2026-07-03分バックフィルレポート） |
| CVE-2026-48277 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS10.0・事前認証RCE・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48281 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS10.0・事前認証RCE・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48316 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS10.0・事前認証RCE・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48282 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | active_exploitation | 2026-07-07 | YES | CVSS10.0・事前認証RCE（任意ファイル書き込み）・参考B採用（APSB26-68内の複合脆弱性）／KEVIntel創業者がハニーポットで実悪用を確認（BleepingComputer 2026-07-06）・exploitation_stageをnone→active_exploitationへ更新・KEV未登録・攻撃予報1（T1/E1/fast_72h/確度低・期限2026-07-10）起点・参考B再採用 |
| CVE-2026-48283 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS10.0・ファイル/権限関連・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48313 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS9.3・任意ファイル読み取り・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48307 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS8.8・事前認証RCE・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48285 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS8.6・事前認証RCE・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48315 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS9.3・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-48314 | Adobe ColdFusion（2025 Update 10未満 / 2023 Update 21未満） | 2026-07-03 | none | 2026-07-03 | YES | CVSS6.5・Important・参考B採用（APSB26-68内の複合脆弱性） |
| CVE-2026-22153 | Fortinet FortiOS（SSL-VPN/LDAPエージェントレス認証・FSSO構成） | 2026-07-07 | none | 2026-07-07 | YES | CVSS8.1・LDAP認証バイパス・恒久修正はFortiOS 7.6.5・IPS向け仮想パッチ「FG-VD-10009566.0day」を2026-07-04公開（Security NEXT）・実悪用未確認・参考A採用（国内広範製品トリガー） |
| CVE-2026-20896 | Gitea Docker images（1.26.2以前） | 2026-07-07 | none | 2026-07-07 | YES | CVSS9.8・X-WEBAUTH-USERヘッダ偽装による認証バイパス・Sysdigが初期調査段階のプロービングのみ観測（実悪用未確認）・軸1=6点のため除外・継続監視対象 |
| CVE-2026-46242 | Linuxカーネル epoll（Bad Epoll・6.4以降 / Android含む） | 2026-07-07 | poc_public | 2026-07-07 | YES | CVSS7.8・PoC公開済み（kernelCTF）・実悪用・KEV登録は未確認・軸1=5点のため除外・継続監視対象 |
| CVE-2026-14191 | WinRAR / UnRAR（RAR5リカバリボリューム処理・7.23未満） | 2026-07-07 | none | 2026-07-07 | YES | CVSS7.8（AV:L/UI:R）・CVE-2023-40477類似変種・PoC/実悪用未確認・過去に同系統がロシア系脅威アクターによりウクライナ向けに悪用された実績あり・軸1=3点のため除外 |
| CVE-2026-54428 | Apache HttpComponents Client/Core 5.4.3未満 | 2026-07-07 | none | 2026-07-07 | YES | CVSS7.5・HTTP/2 HPACKデコーダ及びHTTP/1.1メッセージ解析のリソース過剰消費によるDoSのみ・低優先度規則該当のため除外 |
| CVE-2026-54399 | Apache HttpComponents Client/Core 5.4.3未満 | 2026-07-07 | none | 2026-07-07 | YES | CVE-2026-54428と同一アドバイザリ内の複合DoS脆弱性・CVSS7.5・DoSのみのため除外 |
| CVE-2026-40138 | BeyondTrust Remote Support / Privileged Remote Access (PRA) | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.2・事前認証認証バイパス・クラウド修正済み(2026-04-21)/自己ホスト型は25.3.3で修正・実悪用未確認・参考B採用 |
| CVE-2026-11405 | Tenda ルーター（FH1201/W15E/AC10/AC5/AC6 V2） | 2026-07-08 | poc_public | 2026-07-08 | YES | ハードコードされたバックドア認証情報(CWE-798)・CERT/CC勧告・Nmap検出スクリプト公開・パッチ未提供・JVN発行・参考A採用 |
| CVE-2026-11712 | IBM WebSphere Application Server（管理コンソール） | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.3・管理コンソールヘルプ機能のXSS・暫定修正APAR PH71756・恒久修正2026年Q3予定・Security NEXT国内報道・参考A採用 |
| CVE-2026-11708 | IBM WebSphere Application Server（管理コンソール） | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.3・CVE-2026-11712と同一アドバイザリのXSS・参考A採用 |
| CVE-2026-11595 | IBM WebSphere Application Server（管理コンソール） | 2026-07-08 | none | 2026-07-08 | YES | CVSS4.3・ヘルプシステムのパストラバーサル・同一アドバイザリ内複合脆弱性・参考A採用 |
| CVE-2025-23351 | NVIDIA BlueField DPU / ConnectX | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.0・コマンドインターフェース境界外書き込み・仮想関数(VF)経由・ファームウェア修正2026-06-30リリース済み・Security NEXT国内報道・参考A採用 |
| CVE-2025-23350 | NVIDIA BlueField DPU / ConnectX | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.0・CVE-2025-23351と同一アドバイザリ・参考A採用 |
| CVE-2026-50242 | JetBrains Hub / YouTrack / GoLand / Kotlin | 2026-07-08 | none | 2026-07-08 | YES | CVSS10.0・Hub認証バイパス（DB直接アクセス・管理者権限奪取につながる可能性）・2026年6月修正済み・Security NEXT国内報道・参考A採用 |
| CVE-2026-56142 | JetBrains Hub / YouTrack / GoLand / Kotlin | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.9・認証情報割当経由の権限昇格・同一報道内複合脆弱性・参考A採用 |
| CVE-2026-56141 | JetBrains Hub / YouTrack / GoLand / Kotlin | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.8・弱い疑似乱数生成器によるリカバリコード予測・同一報道内複合脆弱性・参考A採用 |
| CVE-2026-7840 | UltraVNC（Repeater HTTP管理サーバ） | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.8・HTTP管理サーバのバッファオーバーフロー(RCE可能性)・1.8.2.2以前・他8件も同時修正・Security NEXT国内報道・参考A採用 |
| CVE-2026-7839 | UltraVNC（Repeater HTTP管理サーバ） | 2026-07-08 | none | 2026-07-08 | YES | CVSS9.1・初期設定時の設定ファイル不在時デフォルトパスワード使用・同一報道内複合脆弱性・参考A採用 |
| CVE-2026-58315 | セイコーエプソン製プリンター・スキャナー（Web Config） | 2026-07-08 | none | 2026-07-08 | YES | CVSSv3 4.3/v4 5.1・CSRF（CWE-352）・JVN発行・パッチ未提供（回避策あり）・参考A採用 |
| CVE-2026-53359 | Linux kernel KVM（"Januscape"、Intel/AMD） | 2026-07-08 | poc_public | 2026-07-08 | YES | CWE-416 use-after-free（シャドウMMU）・kvmCTFゼロデイ報奨金プログラムで実証・研究用PoC(V4bel/Januscape)公開・16年物バグ・修正済み(コミット81ccda30b4e8)・実悪用未確認・軸1=3点のため除外・継続監視対象 |
