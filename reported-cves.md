# reported-cves.md — 既報CVEリスト

このファイルはタスク実行後に自動更新されます。
新規CVEを追加する際は `CVE-ID | 製品名 | 報告日 | 採用理由` の形式で末尾に追記してください。

## フォーマット
```
CVE-ID | 製品名 | 報告日(YYYY-MM-DD) | 採用理由
```

## 登録済みCVE

<!-- タスク初回実行後、自動追記されます -->
CVE-2026-50751 | Check Point Remote Access VPN / Mobile Access / Spark Firewall | 2026-06-15 | KEV登録・JPCERT+IPA注意喚起・Qilinランサムウェア悪用確認・本編採用
CVE-2026-10520 | Ivanti Sentry | 2026-06-15 | CVSS 10.0・KEV登録・CISA BOD 26-04期限到来・PoC公開・バックドア確認・本編採用
CVE-2026-42897 | Microsoft Exchange Server 2016/2019/SE | 2026-06-15 | CVSS 8.1・JPCERT注意喚起・June Patch Tuesday修正済み・参考A採用
CVE-2026-54420 | LiteSpeed cPanel Plugin (2.4.8未満) | 2026-06-17 | CVSS 8.5・KEV登録・Security NEXT国内報道・共有ホスティングroot権限昇格・参考A採用
CVE-2026-20262 | Cisco Catalyst SD-WAN Manager (複数バージョン) | 2026-06-17 | CVSS 6.5・KEV登録・Security NEXT国内報道・実悪用確認（限定的）・参考A採用
CVE-2026-53435 | Jenkins (2.567以前 / LTS 2.555.2以前) | 2026-06-17 | CVSS 9.0・実悪用確認（ハニーポット）・デシリアライゼーションRCE・参考B採用
CVE-2026-39808 | Fortinet FortiSandbox (4.4.x / 5.0.x) | 2026-06-17 | 未認証OSコマンドインジェクションRCE・PoC公開済み・6/16実悪用観測・参考B採用
CVE-2026-39813 | Fortinet FortiSandbox (4.4.x / 5.0.x) | 2026-06-17 | パストラバーサル・認証バイパス・6/16実悪用観測・参考B採用
CVE-2026-47281 | Microsoft Defender (Windows 10/11 全バージョン) | 2026-06-16 | ゼロデイ未パッチ・CVSS 9.6・PoC公開・実悪用確認・RoguePlanet・本編採用
CVE-2026-35273 | Oracle PeopleSoft Enterprise PeopleTools 8.61/8.62 | 2026-06-16 | CVSS 9.8・KEV登録・BOD 26-04期限6/15到来・ShinyHunters実悪用・ランサムウェア展開・Security NEXT国内報道・本編採用
CVE-2026-5027 | Langflow AIアプリ開発プラットフォーム (1.8.x以前) | 2026-06-18 | CVSS 8.8・VulnCheck KEV登録・実悪用確認・PoC公開・Security NEXT国内報道・本編採用
CVE-2026-50656 | Microsoft Defender (Windows 10/11 全バージョン・完全パッチ適用環境含む) | 2026-06-18 | CVSS 7.8・ゼロデイ（パッチ未提供）・PoC公開（Nightmare Eclipse）・RoguePlanet CVE-2026-47281修正バイパス・参考B採用
CVE-2026-24858 | Fortinet FortiCloud SSO (FortiGate 全バージョン) | 2026-06-19 | CVSS 9.8・SAMLバイパス・FortiBleed大規模クレデンシャル流出（73,932台）・June 18公開・本編採用
CVE-2026-48907 | Widget Factory Joomla Content Editor (JCE) 1.0.0〜2.9.99.4 | 2026-06-19 | CVSS 10.0・KEV登録（2026-06-16）・BOD 26-04期限2026-06-19到来・未認証PHPコード実行・参考B採用
CVE-2026-20253 | Splunk Enterprise 10.2.0〜10.2.3 / 10.0.0〜10.0.6 | 2026-06-21 | CVSS 9.8・KEV登録（2026-06-18）・FCEB期限2026-06-21・未認証RCE（PostgreSQLサイドカー）・実悪用確認・Security NEXT 2026-06-19報道・本編採用
CVE-2026-42530 | NGINX Open Source 1.31.0〜1.31.1 | 2026-06-21 | CVSSv4.0 9.2・HTTP/3 Use-After-Free・未認証RCE条件付き・Security NEXT 2026-06-18報道・参考A採用
CVE-2026-42055 | NGINX Open Source 1.13.10〜1.31.1 / NGINX Plus R30〜R34 | 2026-06-21 | CVSSv4.0 9.2・proxy/grpcモジュールヒープバッファオーバーフロー・未認証RCE条件付き・Security NEXT 2026-06-18報道・参考A採用
CVE-2026-20181 | Cisco Identity Services Engine (ISE / ISE-PIC) 3.3 p11未満 / 3.4 p6未満 / 3.5 | 2026-06-22 | CVSS 9.1・認証済みRCE・CVE-2026-20190との二段階チェーンで実質未認証RCE・Security NEXT 2026-06-18報道・参考A採用
CVE-2026-20190 | Cisco Identity Services Engine (ISE / ISE-PIC) 3.3 p11未満 / 3.4 p6未満 / 3.5 | 2026-06-22 | CVSS 7.1・未認証XXE情報漏洩・CVE-2026-20181への連鎖起点・Security NEXT 2026-06-18報道・参考Aに統合採用
CVE-2026-28318 | SolarWinds Serv-U 15.5.4 Hotfix 1未満 | 2026-06-22 | CVSS 7.5・KEV登録（2026-06-05）・FCEB期限2026-06-19到来・未認証DoS（サービスクラッシュ）・参考B採用
CVE-2026-11645 | Google Chrome / Chromium V8（149.0.7827.102未満） | 2026-06-23 | CVSS 8.8・KEV登録（2026-06-09）・FCEB期限2026-06-23到来・実悪用確認・本編採用
CVE-2026-20245 | Cisco Catalyst SD-WAN Manager（複数バージョン） | 2026-06-23 | CVSS 7.8・KEV登録（2026-06-09）・FCEB期限2026-06-23到来・実悪用確認（ゼロデイ確認後パッチ提供）・参考B採用
CVE-2026-7473 | Arista Extensible Operating System（EOS） | 2026-06-23 | CVSS 6.9・KEV登録・FCEB期限2026-06-23到来・実悪用確認・低優先度フラグ・参考B採用
CVE-2026-4020 | WordPress Gravity SMTPプラグイン（2.1.5未満） | 2026-06-23 | CVSS 5.3・KEV未登録・17M超exploit attempt・API鍵窃取・低優先度フラグ・参考B採用
CVE-2026-8461 | FFmpeg 8.1.2未満（Jellyfin / Nextcloud / Kodi / Emby / OBS Studio等多数） | 2026-06-23 | CVSS 8.8・MagicYUVデコーダ ヒープ境界外書き込み・JFrog RCE実証済み（50KB AVI/MKV）・KEV未登録・参考B採用
CVE-2026-47729 | Squid Proxy 全バージョン（デフォルト設定） | 2026-06-23 | CVSS未公開・Heartbleed類似ヒープover-read・29年物FTPゲートウェイバグ・パッチ未提供（7.7予定）・低優先度フラグ・参考B採用
CVE-2026-10735 | ShapedPlugin WordPress Proプラグイン（Product Slider Pro 3.5.4未満 / Real Testimonials Pro 3.2.5 / Smart Post Show Pro 4.0.2未満） | 2026-06-23 | CVSS 9.8・サプライチェーン攻撃・バックドア埋込・webshell・TOTP窃取・C2 194.76.217.28・参考B採用
CVE-2026-49777 | ShapedPlugin Product Slider Pro for WooCommerce（3.5.4未満） | 2026-06-23 | CVSS 10.0・CVE-2026-10735と同一インシデント・任意ファイル書き込み・参考B統合採用
CVE-2026-7273 | Zyxel GS1900シリーズ スイッチ（2.90.x.1C0以前） | 2026-06-23 | CVSS 8.8・LAN-based未認証OSコマンドインジェクション・スタックバッファオーバーフロー・Security NEXT国内報道・参考A採用
CVE-2026-0533 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | Stored XSS→コード実行・ユーザー操作要・デザイン名ペイロード・Security NEXT国内報道・参考A採用
CVE-2026-0534 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | Stored XSS→コード実行・部品属性ペイロード・Security NEXT国内報道・参考A統合採用
CVE-2026-0535 | Autodesk Fusion（最新パッチ未適用） | 2026-06-23 | Stored XSS→コード実行・コンポーネント説明ペイロード・Security NEXT国内報道・参考A統合採用
CVE-2026-45585 | Microsoft Windows BitLocker（Windows 11 24H2/25H2/26H1・Server 2022/2025） | 2026-06-24 | CVSS 6.8・ゼロデイ（パッチ2026-06-10提供済み）・PoC公開（Nightmare Eclipse/YellowKey）・BitLockerバイパス・ゼロデイ特報採用
CVE-2026-34908 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・未認証アクセス制御バイパス・RCEチェーン起点・Security NEXT国内報道・本編採用
CVE-2026-34909 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・パストラバーサル・RCEチェーン構成・本編採用
CVE-2026-34910 | Ubiquiti UniFi OS Server 5.0.6以前 | 2026-06-24 | CVSS 10.0・KEV登録（2026-06-23）・FCEB期限2026-06-26・コマンドインジェクション・root RCE・本編採用
CVE-2025-67038 | Lantronix EDS5000 2.1.0.0R3以前 | 2026-06-24 | CVSS 9.8・KEV登録（2026-06-23）・FCEB期限2026-06-26・未認証root権限コマンドインジェクション・Security NEXT国内報道・本編採用
CVE-2026-20230 | Cisco Unified Communications Manager / Unified CM SME 14.x（14SU6未満）/ 15.x（15SU5未満） | 2026-06-24 | CVSS 8.6・Cisco Critical SIR・PoC公開（SSD 2026-06-24）・実悪用確認（Tor経由ウェブシェル展開 2026-06-22〜24）・KEV未登録・本編採用
CVE-2026-8732 | WP Maps Pro WordPress プラグイン 6.1.0以前 | 2026-06-24 | CVSS 9.8・実悪用確認（Wordfence 24h 2,858件ブロック）・未認証管理者アカウント作成・本編採用
CVE-2026-11374 | ManageEngine ADSelfService Plus 6528以前 / RecoveryManager Plus 6320以前 / M365 Manager Plus 4816以前 / ADAudit Plus 8702以前 | 2026-06-24 | CVSS 9.0・SSO認証チケット予測によるアカウント乗っ取り・Security NEXT国内報道・参考A採用
CVE-2026-24155 | NVIDIA NeMo AIフレームワーク 2.7.2以前 | 2026-06-24 | CVSS 7.8・コードインジェクション・Security NEXT国内報道・参考A採用
CVE-2026-24252 | NVIDIA NeMo AIフレームワーク 2.7.2以前（Linux） | 2026-06-24 | CVSS 7.8・OSコマンドインジェクション・Security NEXT国内報道・参考A統合採用
CVE-2026-24228 | NVIDIA NeMo AIフレームワーク 2.7.2以前（Linux） | 2026-06-24 | CVSS 7.8・安全でないデシリアライゼーション・Security NEXT国内報道・参考A統合採用
CVE-2026-41089 | Windows Server 2012 R2〜2025（Netlogonサービス） | 2026-06-24 | CVSS 9.8・未認証0-click RCE・ドメインコントローラ完全掌握・ベルギーCCB実悪用確認（2026-05-29）・KEV未登録・参考B採用
CVE-2026-49975 | Apache HTTP Server 2.4.17〜2.4.67（mod_http2） | 2026-06-24 | CVSS 8.7(v4)/7.5(v3.1)・HTTP/2 Bomb DoS・PoC公開・4000倍増幅・参考B採用
CVE-2026-44963 | Veeam Backup & Replication 12.3.2.4465以前（バージョン12系） | 2026-06-25 | CVSS 9.4・PoC公開（GitHub 2026-06-10）・BleepingComputer/THN 2026-06-24〜25報道・ドメインユーザー認証RCE・パッチ提供済み（12.3.2.4854）・参考B採用
CVE-2026-13028 | Google Chrome 149.0.7827.196未満（WebGL） | 2026-06-26 | Google Critical・WebGL Use-After-Free・サンドボックス脱出の起点となりうる構造・Security NEXT 2026-06-25報道（記事186374）・PoC未公開・参考A採用
CVE-2026-13032 | Google Chrome 149.0.7827.196未満（WebGL） | 2026-06-26 | Google Critical・WebGL Use-After-Free・Google内部発見・CVE-2026-13028とチェーン悪用リスク・Security NEXT 2026-06-25報道・PoC未公開・参考A採用
CVE-2026-13033 | Google Chrome 149.0.7827.196未満（Blink InterestGroups） | 2026-06-26 | Google Critical・Protected Audience API境界外読み取り・Security NEXT 2026-06-25報道・PoC未公開・参考A採用
CVE-2026-13038 | Google Chrome 149.0.7827.196未満（Autofill） | 2026-06-26 | Google Critical・Autofill関連・詳細未公表・認証情報窃取チェーン悪用リスク・Security NEXT 2026-06-25報道・PoC未公開・参考A採用
CVE-2026-13281 | Google Chrome 149.0.7827.201未満（Mojo） | 2026-06-26 | Google High・Mojo整数オーバーフロー・CWE-190・レンダラ侵害後のサンドボックス脱出起点・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用
CVE-2026-13282 | Google Chrome 149.0.7827.201未満（Payments） | 2026-06-26 | Google High・Payments Use-After-Free・CWE-416・決済情報窃取リスク・Googleが2026-05-28発見・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用
CVE-2026-13283 | Google Chrome 149.0.7827.201未満（AdFilter） | 2026-06-26 | Google High・AdFilter Use-After-Free・CWE-416・Googleが2026-06-11発見・Security NEXT 2026-06-25報道（記事186427）・PoC未公開・参考A採用
CVE-2026-12569 | PTC Windchill PDMlink / FlexPLM 13.0 M010以前 | 2026-06-26 | CVSS 9.8・CWE-502デシリアライゼーションRCE・KEV 2026-06-25登録・FCEB期限2026-06-28・JSP Webシェル実悪用継続・C2 IP 5.180.41.35・参考B採用
CVE-2026-12569 | PTC Windchill PDMlink / FlexPLM 11.0 M030未満 | 2026-06-27 | CVSS 9.3・KEV登録（2026-06-25）・FCEB期限2026-06-28・JSP Webシェル展開継続（PTC公式確認）・実悪用確認・バースト閾値超過6ソース・本編採用
CVE-2026-20230 | Cisco Unified Communications Manager / Unified CM SME 14.x/15.x | 2026-06-27 | CVSS 8.6・KEV登録（2026-06-25、既報2026-06-24からKEV未登録→登録のステータス変化）・FCEB期限2026-06-28・パッチ後Webシェル残存確認（/platform-services/axis2-web/）・本編再採用
CVE-2026-46331 | Linux kernel net/sched/act_pedit（v5.18〜v7.1-rc6） | 2026-06-27 | High相当・PoC公開（packet_edit_meme）・RHEL 8/9/10・Debian 13での特権昇格確認・pedit COW・Kubernetes環境エスケープリスク・参考B採用
CVE-2026-13136 / CVE-2026-13135 / CVE-2025-15660 | Synology MailPlus Server 4.0.1-31663未満 | 2026-06-27 | Critical相当・不正認証チェック（任意ファイルR/W・DoS）・通信チャネル不適切制限（内部サービスアクセス）・弱PRNG（任意ファイルアクセス・DoS）の3件・Synology SA-26:11・Help Net Security 2026-06-26報道・参考B採用
CVE-2026-43503 | Linux kernel (net/sched DirtyClone) < 7.1-rc5 | 2026-06-28 | CVSS 8.8・CWE-362競合状態LPE・JFrog PoC公開2026-06-25・THN/BleepingComputer 2026-06-27報道・Kubernetes環境コンテナエスケープリスク・参考B採用
