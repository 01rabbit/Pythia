# reported-apts.md — 既報APT活動リスト

このファイルはタスク実行後に状態遷移ベースで更新されます。
同一活動は `活動ID / キャンペーン名` をキーに更新し、再掲ではなく `最終状態` と `最終更新日` を更新してください。

## アーカイブ規定

毎月1日、継続監視=NO かつ 最終更新日から30日超の行を `reported-apts-YYYY-MM.md`（cves/ai-attacksも同形式）へ移動する。
アーカイブ済み事案が再燃した場合は新規行として再登録し、備考にアーカイブ元を記載する。

## フォーマット

| グループ名 | 活動ID / キャンペーン名 | 初報日 | 最終状態 | 最終更新日 | 継続監視 | 備考 |
|------------|------------------------|--------|----------|------------|----------|------|
| Velvet Ant | Velvet-Ant-2026-OperationHighland | 2026-06-17 | 活動継続 | 2026-06-17 | YES | Sygnia公開・中国nexus帰属・10年間エアギャップ潜伏・PAMバックドア・OpenSSH改ざん・注目動向採用 |
| 不明（帰属未確定） | AtomicArch-2026-AURSupplyChain | 2026-06-17 | 活動継続 | 2026-06-17 | YES | AUR 1500+パッケージ侵害・eBPFルートキット+インフォスティーラー配布・サプライチェーン攻撃・注目動向採用 |
| Screening Serpens | ScreeningSerpens-2026-EpicFury-MiniUpdate | 2026-06-18 | 活動継続 | 2026-06-18 | YES | IRGC関連・Unit 42追跡報告・MiniUpdate/MiniJunk V2新規RATファミリー・AppDomainManagerハイジャック新規TTP・米国/イスラエル/UAE標的・注目動向採用 |
| UNC6508 | UNC6508-2026-REDCap-INFINITERED | 2026-06-19 | 活動継続 | 2026-06-19 | YES | 中国(PRC)nexus・Google Mandiant初報2026-06-15・REDCapサーバ侵害・INFINITERED新規マルウェア・Google Workspace BCC転送悪用・医療/軍事研究機関標的・本編採用 |
| 不明（Russian-speaking IAB / 帰属信頼度: 中） | FortiBleed-2026-CredentialCampaign | 2026-06-22 | 本編昇格 | 2026-07-02 | YES | FortiGate 86,644台（更新: 73,932→86,644台）の有効認証情報公開・SecurityWeek新規詳細レポート2026-06-20〜21・194カ国・少なくとも4組織完全侵害確認・注目動向更新採用 / 規模最終更新: 430,000台超・110M超認証情報（既報86,644台から5倍超に拡大）・BleepingComputer/Cryptika/THN 2026-06-25報道・ランサムウェアグループへのアクセス販売継続・注目動向更新採用 / SOCRadar調査（BleepingComputer 2026-07-02報道）: 感染基盤内WindowsサーバからINC・Lynx両ランサムウェアグループの交渉パネルへのアクセスを確認、盗取VPN認証情報のマネタイズ経路（ランサムウェアグループへの転売）判明。スニッファー展開台数19,000台（通知後11,000台）・運用サーバ約500台・追加インフラ200件超・運用メンバー推定20名・バックドアアカウント「adminin」確認・未公開Nextcloudゼロデイ悪用の疑い浮上。軸P9・軸Q8で本編採用・攻撃予報1（T1/E2/fast_72h/確度低・期限2026-07-05）起点 |
| Gentlemen（RaaS / 帰属未確定） | Gentlemen-2026-GentleKillerByovd | 2026-06-21 | 活動継続 | 2026-06-21 | YES | ESET技術分析2026-06-18公開・GentleKiller 8バリアントBYOVD・478被害組織・70カ国以上・EDRキラーRaaS・本編採用 |
| Icarus（恐喝グループ） | Icarus-2026-KlueSalesforceOAuth | 2026-06-21 | 活動継続 | 2026-06-21 | YES | Klue OAuth侵害によるSalesforce CRMデータ窃取・Huntress/Recorded Future等複数セキュリティ企業影響・2026-06-19 BleepingComputer/Help Net報道・注目動向採用 |
| Sapphire Sleet（北朝鮮DPRK / BlueNoroff / APT38） | SapphireSleet-2026-MastraNpmSupplyChain | 2026-06-23 | 活動継続 | 2026-06-23 | YES | Microsoft高信頼帰属・Mastra npm 144パッケージ侵害・88分全自動・postinstall PowerShellバックドア・scdev永続化サービス・DPRK北朝鮮・本編採用 |
| Andariel（北朝鮮DPRK / Onyx Sleet / Lazarusサブグループ） | Andariel-2026-FullDisclosure-AhnLab | 2026-06-23 | 活動継続 | 2026-06-23 | YES | AhnLab ASEC Full Disclosure 2026-06-23公開・TigerRAT/StarshellRAT/JelusRAT/GopherRAT Go製新規マルウェア・欧州公共機関・韓国ERP標的・注目動向採用 |
| 不明（帰属未確定） | AryStinger-2026-DLinkBotnet | 2026-06-23 | 活動継続 | 2026-06-23 | YES | D-Link DIR-850L/DIR-818LW・QNAP NAS 4,300台以上侵害・偵察プロキシボットネット・韓国48.5%・中国31.8%・XLab発見・複数ソース・注目動向採用 |
| Prinz Eugen（新規ランサムウェアグループ / 帰属未確定） | PrinzEugen-2026-RecentFileRansomware | 2026-06-23 | 活動継続 | 2026-06-23 | YES | 新規Go製ランサムウェア・最近更新ファイル優先暗号化・RMMツール悪用・ランサムノートなし・5被害組織確認・注目動向採用 |
| 不明（Russian-speaking財務動機 / 帰属信頼度:中） | REF8372-2026-OXLOADER-CastleStealer | 2026-06-23 | 活動継続 | 2026-06-23 | YES | Elastic Security Labs 2026-06-22初報・悪意あるGoogle Ads→偽Node.js→OXLOADER→CastleStealer・DLLサイドローディング・IAT難読化・CIS除外設定・開発者標的・注目動向採用 |
| 不明（Chinese-speaking低確度） | WhatsApp-VBScript-2026-ManageEngine | 2026-06-23 | 活動継続 | 2026-06-23 | YES | Kaspersky 2026-06-22初報・WhatsApp偽業務文書VBScript配布・ManageEngine Endpoint Central RMM永続化・Malaysia 80%・多国間アクティブ継続・ValleyRAT/Gh0stインフラ重複・注目動向採用 |
| 不明（帰属未確定） | KDDI-2026-EmailSystemBreach | 2026-06-23 | 活動継続 | 2026-06-23 | YES | Security NEXT 2026-06-23報道・最大1422万件メールアドレス+パスワード漏洩・6ISP影響・2026-06-17検知・国内重大インシデント・クレデンシャルスタッフィングリスク・注目動向採用 |
| Nightmare Eclipse | NightmareEclipse-2026-WindowsZeroDayDisclosure | 2026-06-24 | 活動継続 | 2026-06-24 | YES | 個人/小グループ・Windows脆弱性連続開示キャンペーン・YellowKey(CVE-2026-45585 BitLockerバイパス)・GreenPlasma PoC公開・CVE-2026-50656修正バイパス・注目動向採用 |
| KongTuke（初期アクセスブローカー / 帰属未確定） | KongTuke-2026-Mistic-IAB | 2026-06-25 | 活動継続 | 2026-06-25 | YES | Symantec/Carbon Black 2026-06-24初報・BleepingComputer 2026-06-25報道・Misticファイルレスバックドア・MpExtMs.exe DLLサイドローディング・ClickFix配信・Qilin/Interlock/Rhysida/Akira/8Base/Black Bastaの6ランサムウェアグループへのアクセス販売・保険/教育/IT/専門サービス標的・注目動向採用 |
| 不明（DPRK/BONZAI関連 / 帰属信頼度: 高） | Gaslight-2026-macOSBONZAI | 2026-06-25 | 活動継続 | 2026-06-25 | YES | SentinelOne 2026-06-23初報・BleepingComputer/THN 2026-06-24〜25報道・Rust製macOSバックドア・38種偽システムメッセージによるAIプロンプトインジェクション回避・Telegram C2・Chrome/Brave/Firefox/Safari認証情報窃取・macOSキーチェーン窃取・注目動向採用 |
| Turla（Venomous Bear / Snake / IRON HUNTER / JOVIAL SERPENT / Waterbug / Krypton / UNC4210） | Turla-2026-STOCKSTAY-EspionageCampaign | 2026-06-26 | 活動継続 | 2026-06-27 | YES | Google GTIG 2026-06-26公開・RU FSB Center 16帰属・新規.NET 4コンポーネントバックドアSTOCKSTAY・WebSocket C2（RSA 4096）・KAZUARコード重複・ウクライナ政府軍事組織/欧州外交機関標的・C2インフラ onrender.com/glitch.me・本編採用／websocket-sharp実装詳細・CVE-2025-8088 WinRAR悪用RAR配布を追加確認・本編採用（旧キー Turla-2026-STOCKSTAY-Ukraine はエイリアス。同一Google GTIG 2026-06-26初報キャンペーンの重複登録のため本キーへ統合） |
| APT28（Fancy Bear / Pawn Storm / STRONTIUM / Forest Blizzard） | APT28-2026-PRISMEX-NATOLogistics | 2026-06-28 | 活動継続 | 2026-06-28 | YES | Trend Micro/SecurityAffairs/THN 2026-06-27詳細分析・PRISMEX新規マルウェア（ドロッパー+ローダー+インプラント）・COMハイジャックCLSID {D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}・CVE-2026-21509/21513悪用・Filen.io C2ステガノグラフィ・ウクライナ/NATO同盟国防衛ロジスティクス標的・本編採用 |
| Russian Intelligence Services（FSB Unit 26165 / UNC5792 / UNC4221） | RIS-2026-SignalBackupKey-PSA260626 | 2026-06-28 | 活動継続 | 2026-06-29 | YES | FBI/CISA PSA260626 2026-06-26公開・Signalバックアップ鍵窃取・デバイスリンクQRコード偽装によるアカウント完全複製・政府機関・軍人・ジャーナリスト・外交官標的・本編採用／DoJ 2026-06-28 $10M報奨金発表（FSB Unit 26165 将校指名手配）・帰属更新（高信頼度）・本編採用 |
| StrikeShark（中国語話者系APT / 帰属信頼度: 低） | StrikeShark-2026-SharkLoaderDiplomacy | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Kaspersky GReAT 2026-06-24初報・The Hacker News 2026-06-26報道・SharkLoader新規カスタムドロッパー+Cobalt Strike Beacon・CVE-2021-26855/CVE-2023-32315/CVE-2024-36401悪用・DLL サイドローディング（T1574.002）・LSASS/NTDS認証情報窃取・インドネシア/台湾/香港/レバノン等の外交・政府機関標的・本編採用 |
| TraderTraitor（DPRK / Lazarus Group / Jade Sleet / APT38） | TraderTraitor-2026-KelpDAO-DriftUK | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Chainalysis/FBI 2026-06-28初報・LinkedIn経由DeFi開発者標的・KelpDAO/DriftUK スマートコントラクト改ざん・npm悪意あるパッケージ（T1195.002）・JavaScriptバックドア（T1059.007）・T1565.001データ操作・NpmBackdoor/GoInjectマルウェア・本編採用 |
| Sapphire Sleet（DPRK / BlueNoroff / CryptoCore / APT38） | SapphireSleet-2026-TrilatSummit | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Microsoft Threat Intelligence 2026-06-28初報・日米韓三カ国首脳会談テーマ偽招待状スピアフィッシング（T1566）・RustyHookマルウェア・金融/防衛/政府/シンクタンク標的・日本/韓国/米国/欧州対象・本編採用 |
| CL-STA-1062（帰属未確定 / 中国語話者系APTの可能性・Unit 42 追跡） | CLSTA1062-2026-TinyRCT | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Unit 42 2026-06-27初報・Confluence/ServiceNow既知脆弱性悪用（T1190）・TinyRCT新規RATバックドア・PowerShell実行（T1059）・東南アジア/中東の通信/政府/製造業標的・本編採用 |
| Silver Fox APT（中国語話者系APT / Hiding Elephant / 帰属信頼度: 中） | SilverFox-2026-Gh0stCringe-HoldingHands | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Kaspersky GReAT 2026-06-27初報・Gh0stCringe RAT + HoldingHands新規スティーラー・VBScript/PowerShell実行（T1059）・多段難読化（T1027）・東南アジア/台湾の金融/製造/IT標的・本編採用 |
| 不明（イラン系APT / PHOSPHORUS/Mint Sandstorm技術的重複 / 帰属信頼度: 低） | IranianAPTs-2026-Q2-DenoRuntime | 2026-06-29 | 活動継続 | 2026-06-29 | YES | Check Point/Mandiant 2026-06-28初報・Deno ランタイムをLiving off the Land技術として利用（DenoAgent）・中東/欧州/米国の政府/防衛/エネルギー標的・本編採用 |
| Mustang Panda（TA416 / RedDelta / Bronze President / Earth Preta） | MustangPanda-2026-ZohoWorkDriveIndia | 2026-06-30 | 活動継続 | 2026-06-30 | YES | Acronis TRU 2026-06-29初報・インド政府機関水力発電セクター+台湾関連MOU機関標的の2並行キャンペーン・新規ツールSHARDLOADER/MINIRECON/ZOHOMURK・Zoho WorkDriveをC2デッドドロップに悪用（T1102）・CERT-In連携・本編採用 |
| Gamaredon（Primitive Bear / Shuckworm / Armageddon / UAC-0010） | Gamaredon-2026-GammaEcosystem-CloudC2 | 2026-06-30 | 活動継続 | 2026-06-30 | YES | The Hacker News 2026-06-29初報・マルウェアアーセナルを「Gamma」エコシステムへ再編（GammaPhish/GammaLoad/GammaWorm/GammaSteel）・正規クラウドストレージをC2悪用（T1102）・ウクライナ政府/軍事機関標的・35件新規スピアフィッシングキャンペーン・本編採用 |
| 不明（帰属未確定） | Aflac-2026-JapanCustomerDataBreach | 2026-06-30 | 活動継続 | 2026-07-01 | YES | BleepingComputer/Nikkei Asia/Security Affairs/The Record 2026-06-30初報・Aflac Japan契約者専用サイトへの不正アクセス（2026-06-15〜25）・顧客/代理店約438万人分の個人情報流出（うち約23万人分は保険料振替口座情報含む）・攻撃者/侵入手口未特定・米SEC 8-K開示・金融庁通知・注目動向採用・攻撃予報2026-06-30予報2（slow_7d・期限2026-07-07）で継続追跡中 |
| 不明（北朝鮮nexus・具体的グループ名は本キャンペーンに未帰属） | RIS-2026-RollupPolyfillNpmSupplyChain | 2026-07-04 | 活動継続 | 2026-07-04 | YES | JFrog調査・The Hacker News 2026-07-04報道・正規パッケージ「rollup-plugin-polyfill-node」模倣npmサプライチェーン攻撃・npmトークン/クラウド鍵/AIサービス認証情報(Claude/Gemini)/SSH鍵標的・C2 216.126.236.244・軸P8軸Q3で注目動向採用・攻撃予報1（T2/E2/fast_72h/確度低・期限2026-07-07）起点 |
| ToddyCat（中国nexus） | ToddyCat-2026-UmbrijOAuthGmail | 2026-07-03 | 活動継続 | 2026-07-03 | YES | Kaspersky Securelist初報2026-06-30・The Hacker News追跡報道2026-07-02・新規ツール「Umbrij」（.NET製）・OAuth経由パスワード窃取なしGmailアクセス（Shadow Token via Remote Debug）・DLLサイドローディング配布・OAuthクライアントID 279448736670/1095133494869・注目動向採用（2026-07-03分バックフィルレポート） |
