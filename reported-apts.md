# reported-apts.md — 既報APT活動リスト

このファイルはタスク実行後に自動更新されます。
新規エントリを追加する際は以下のフォーマットで末尾に追記してください。

## フォーマット

```
グループ名 | 活動ID / キャンペーン名 | 報告日(YYYY-MM-DD) | 採用理由
```

- 活動ID: グループ名 + 簡潔なキャンペーン識別子（例: APT29-2026Q2-Embassy）
- 変化があった場合は同一IDで日付を更新して再報告してよい

## 登録済みエントリ

<!-- タスク初回実行後、自動追記されます -->
Velvet Ant | Velvet-Ant-2026-OperationHighland | 2026-06-17 | Sygnia公開・中国nexus帰属・10年間エアギャップ潜伏・PAMバックドア・OpenSSH改ざん・注目動向採用
不明（帰属未確定） | AtomicArch-2026-AURSupplyChain | 2026-06-17 | AUR 1500+パッケージ侵害・eBPFルートキット+インフォスティーラー配布・サプライチェーン攻撃・注目動向採用
Screening Serpens | ScreeningSerpens-2026-EpicFury-MiniUpdate | 2026-06-18 | IRGC関連・Unit 42追跡報告・MiniUpdate/MiniJunk V2新規RATファミリー・AppDomainManagerハイジャック新規TTP・米国/イスラエル/UAE標的・注目動向採用
UNC6508 | UNC6508-2026-REDCap-INFINITERED | 2026-06-19 | 中国(PRC)nexus・Google Mandiant初報2026-06-15・REDCapサーバ侵害・INFINITERED新規マルウェア・Google Workspace BCC転送悪用・医療/軍事研究機関標的・本編採用
不明（Russian-speakingグループ帰属推定） | FortiBleed-2026-CredentialCampaign | 2026-06-22 | FortiGate 86,644台（更新: 73,932→86,644台）の有効認証情報公開・SecurityWeek新規詳細レポート2026-06-20〜21・194カ国・少なくとも4組織完全侵害確認・注目動向更新採用
Gentlemen（RaaS / 帰属未確定） | Gentlemen-2026-GentleKillerByovd | 2026-06-21 | ESET技術分析2026-06-18公開・GentleKiller 8バリアントBYOVD・478被害組織・70カ国以上・EDRキラーRaaS・本編採用
Icarus（恐喝グループ） | Icarus-2026-KlueSalesforceOAuth | 2026-06-21 | Klue OAuth侵害によるSalesforce CRMデータ窃取・Huntress/Recorded Future等複数セキュリティ企業影響・2026-06-19 BleepingComputer/Help Net報道・注目動向採用
Sapphire Sleet（北朝鮮DPRK / BlueNoroff / APT38） | SapphireSleet-2026-MastraNpmSupplyChain | 2026-06-23 | Microsoft高信頼帰属・Mastra npm 144パッケージ侵害・88分全自動・postinstall PowerShellバックドア・scdev永続化サービス・DPRK北朝鮮・本編採用
Andariel（北朝鮮DPRK / Onyx Sleet / Lazarusサブグループ） | Andariel-2026-FullDisclosure-AhnLab | 2026-06-23 | AhnLab ASEC Full Disclosure 2026-06-23公開・TigerRAT/StarshellRAT/JelusRAT/GopherRAT Go製新規マルウェア・欧州公共機関・韓国ERP標的・注目動向採用
不明（帰属未確定） | AryStinger-2026-DLinkBotnet | 2026-06-23 | D-Link DIR-850L/DIR-818LW・QNAP NAS 4,300台以上侵害・偵察プロキシボットネット・韓国48.5%・中国31.8%・XLab発見・複数ソース・注目動向採用
Prinz Eugen（新規ランサムウェアグループ / 帰属未確定） | PrinzEugen-2026-RecentFileRansomware | 2026-06-23 | 新規Go製ランサムウェア・最近更新ファイル優先暗号化・RMMツール悪用・ランサムノートなし・5被害組織確認・注目動向採用
不明（Russian-speaking財務動機 / 帰属信頼度:中） | REF8372-2026-OXLOADER-CastleStealer | 2026-06-23 | Elastic Security Labs 2026-06-22初報・悪意あるGoogle Ads→偽Node.js→OXLOADER→CastleStealer・DLLサイドローディング・IAT難読化・CIS除外設定・開発者標的・注目動向採用
不明（Chinese-speaking低確度） | WhatsApp-VBScript-2026-ManageEngine | 2026-06-23 | Kaspersky 2026-06-22初報・WhatsApp偽業務文書VBScript配布・ManageEngine Endpoint Central RMM永続化・Malaysia 80%・多国間アクティブ継続・ValleyRAT/Gh0stインフラ重複・注目動向採用
不明（帰属未確定） | KDDI-2026-EmailSystemBreach | 2026-06-23 | Security NEXT 2026-06-23報道・最大1422万件メールアドレス+パスワード漏洩・6ISP影響・2026-06-17検知・国内重大インシデント・クレデンシャルスタッフィングリスク・注目動向採用
Nightmare Eclipse | NightmareEclipse-2026-WindowsZeroDayDisclosure | 2026-06-24 | 個人/小グループ・Windows脆弱性連続開示キャンペーン・YellowKey(CVE-2026-45585 BitLockerバイパス)・GreenPlasma PoC公開・CVE-2026-50656修正バイパス・注目動向採用
KongTuke（初期アクセスブローカー / 帰属未確定） | KongTuke-2026-Mistic-IAB | 2026-06-25 | Symantec/Carbon Black 2026-06-24初報・BleepingComputer 2026-06-25報道・Misticファイルレスバックドア・MpExtMs.exe DLLサイドローディング・ClickFix配信・Qilin/Interlock/Rhysida/Akira/8Base/Black Bastaの6ランサムウェアグループへのアクセス販売・保険/教育/IT/専門サービス標的・注目動向採用
不明（DPRK/BONZAI関連 / 帰属信頼度: 高） | Gaslight-2026-macOSBONZAI | 2026-06-25 | SentinelOne 2026-06-23初報・BleepingComputer/THN 2026-06-24〜25報道・Rust製macOSバックドア・38種偽システムメッセージによるAIプロンプトインジェクション回避・Telegram C2・Chrome/Brave/Firefox/Safari認証情報窃取・macOSキーチェーン窃取・注目動向採用
Turla（Venomous Bear / Snake / IRON HUNTER / JOVIAL SERPENT / Waterbug / Krypton） | Turla-2026-STOCKSTAY-EspionageCampaign | 2026-06-26 | Google GTIG 2026-06-26公開・RU FSB Center 16帰属・新規.NET 4コンポーネントバックドアSTOCKSTAY・WebSocket C2（RSA 4096）・KAZUARコード重複・ウクライナ政府軍事組織/欧州外交機関標的・C2インフラ onrender.com/glitch.me・本編採用
Turla（Snake / Venomous Bear / Waterbug / IRON HUNTER / UNC4210） | Turla-2026-STOCKSTAY-Ukraine | 2026-06-27 | Google GTIG 2026-06-26初報・新型.NETバックドアSTOCKSTAY・websocket-sharp WebSocket C2・KazuarとコードDNA重複・CVE-2025-8088 WinRAR悪用RAR配布・ウクライナ軍/政府機関・欧州外交機関標的・本編採用
不明（Russian-speaking IAB / 帰属信頼度: 中） | FortiBleed-2026-CredentialCampaign | 2026-06-27 | 規模最終更新: 430,000台超・110M超認証情報（既報86,644台から5倍超に拡大）・BleepingComputer/Cryptika/THN 2026-06-25報道・ランサムウェアグループへのアクセス販売継続・注目動向更新採用
