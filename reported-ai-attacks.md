# reported-ai-attacks.md — 既報AI攻撃インシデントリスト

このファイルはAI攻撃インテリジェンスタスク実行後に状態遷移ベースで更新されます。
同一インシデントは再掲せず、`インシデント名 / CVE等` をキーに `最終状態` と `最終更新日` を更新してください。

## アーカイブ規定

毎月1日、継続監視=NO かつ 最終更新日から30日超の行を `reported-ai-attacks-YYYY-MM.md`（cves/aptsも同形式）へ移動する。
アーカイブ済み事案が再燃した場合は新規行として再登録し、備考にアーカイブ元を記載する。

## フォーマット

| インシデント名 / CVE等 | カテゴリ | 初報日 | 最終状態 | 最終更新日 | 継続監視 | 備考 |
|--------------------------|----------|--------|----------|------------|----------|------|
| Agentjacking（SentryMCP経由） | C3・A4 | 2026-06-19 | 継続監視 | 2026-06-19 | YES | Tenet Security実証・2,388組織露出・85%成功率・本編採用 |
| LiteLLM PyPI供給チェーン侵害（TeamPCP） | C6 | 2026-06-19 | 継続監視 | 2026-06-19 | YES | 47,000DL・9500万月間DLのパッケージ感染・本編採用 |
| CVE-2026-7482（Ollama Bleeding Llama） | C1 | 2026-06-19 | 継続監視 | 2026-06-19 | YES | CVSS 9.1・300,000台露出・未認証メモリリード・参考B採用 |
| OWASP State of Agentic AI Security 2026 v2.01 | B1・C3全般 | 2026-06-19 | 継続監視 | 2026-06-19 | YES | OWASP包括的レポート・実CVE紐付き・参考B採用 |
| AI生成フィッシング集団→個別最適化移行（Zscaler 2026-06-12） | A1 | 2026-06-19 | 継続監視 | 2026-06-19 | YES | Zscalerレポート・日本語AI生成フィッシング増加・参考A採用 |
| LLMjacking Evolved: VAPTアジェンティックフレームワーク / Ollama自律攻撃エンジン悪用 | A4 | 2026-06-27 | 継続監視 | 2026-06-27 | YES | CSA/Sysdig 2026-06-26・露出Ollamaを自律型ペネトレーションフレームワーク(VAPT)の推論エンジンとして悪用・175,000台超認証なし露出・4セッション15時間実運用確認・バースト閾値超過5ソース・本編採用 |
| macOS.Gaslight AIプロンプトインジェクション回避（DPRK BONZAI） | B1 | 2026-06-28 | 継続監視 | 2026-06-28 | YES | THN/TechTimes 2026-06-27詳報・38個の偽システムメッセージでLLMベースAIマルウェア解析ツールを誤誘導・北朝鮮DPRK/BONZAI帰属・バーストカウント5件（threshold_met）・参考B採用 |
| Djinn Stealer: CVE-2026-48558経由AI開発者認証情報・MCPコンフィグ窃取 | C3 | 2026-06-29 | 継続監視 | 2026-07-01 | YES | BleepingComputer/Horizon3.ai/HelpNetSecurity 2026-06-29・CVE-2026-48558（SimpleHelp CVSS 10.0 OIDC認証バイパス）経由・Claude/Gemini/Codex/Cline/OpenCode/Kilo等AI開発者設定・MCPコンフィグ・SSH/クラウド/Docker/Terraform認証情報窃取・バーストカウント3件（threshold_met）・本編採用（AI-2026-06-29-001） / TaskWeaver（jquery.js偽装Node.jsローダー、a.dev-tunnels[.]com通信）を第1段階とする二段階攻撃チェーンであることが判明・バーストカウント8件（burst_exceeded）・本編再採用（AI-2026-07-01-002） |
| BioShocking: ゲーム型間接プロンプトインジェクションでAIブラウザから認証情報窃取 | B1 | 2026-07-01 | 継続監視 | 2026-07-01 | YES | LayerX/The Hacker News/BleepingComputer/Infosecurity Magazine 2026-06-30・ChatGPT Atlas/Perplexity Comet/Claude Chrome拡張/Fellou/Genspark Browser/Sigma Browserの6種のAIブラウザ対象・誤答報酬パズルでガードレール段階的無効化・ログイン済みGitHubアカウントから認証情報窃取実証（実被害未確認）・OpenAIは修正済みだがPerplexityは対応見送り・バーストカウント7件（burst_exceeded）・本編採用（AI-2026-07-01-001） |
| LiteLLM CVE-2026-42271 SSRF（AI ゲートウェイ内部偵察） | C1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | GitHub Advisory/NIST/SecurityWeek 2026-06-28・CVSS 9.1・CWE-918 SSRF・LiteLLM 1.42.0以下・1.43.0パッチリリース・PoC公開・内部ネットワーク偵察可能・バーストカウント3件（threshold_met）・参考B採用（AI-2026-06-29-002） |
| Miasma AI ワーム（AI インフラ間自己増殖型マルウェア） | C6 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Wiz Research/DarkReading 2026-06-28・AI インフラ間を自己増殖・MCP サーバー/Ollama インスタンス/Jupyter ノートブックを連鎖侵害・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-003） |
| Gemini 搭載 SMiShing キャンペーン（AI 生成 SMS フィッシング個別最適化） | A1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Zscaler/ThreatPost 2026-06-28・Gemini API 悪用・個人属性ベースの高精度 SMS フィッシング生成・金融/EC ユーザー標的・バーストカウント2件（below_threshold）・参考A採用（AI-2026-06-29-004） |
| Claude Code GitHub Actions プロンプトインジェクション（CI/CD パイプライン乗っ取り） | B1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Wiz Research/HelpNetSecurity 2026-06-28・GitHub PR コメント経由プロンプトインジェクション・Claude Code が CI/CD 内で悪意ある指示を実行・シークレット漏洩/コード改ざんリスク・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-005） |
| OpenClaw Pinchy: オープンソース LLM 自律型ペネトレーションフレームワーク | A4 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Unit 42/DarkReading 2026-06-29・Ollama/llama.cpp 自律 AI エージェントを攻撃推論エンジンに悪用・偵察→脆弱性特定→エクスプロイト選択まで自動化・犯罪グループによる実戦運用確認・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-006） |
| GuardFall: オープンソースAIコーディングエージェントのbashシェルインジェクション | B1 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News/SecurityWeek 2026-06-30・Adversa AI研究・11種中10種のオープンソースAIコーディング/コンピュータ操作エージェントでシェルインジェクション実証成功（Continueのみ防御）・bashコマンド書き換えによるブロックリスト回避・バーストカウント3件（threshold_met）・本編採用（AI-2026-06-30-001） |
| Microsoft MCPツール説明文汚染（Tool Poisoning）警告 | B1 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News 2026-06-30・Microsoft公式セキュリティアドバイザリ・MCPツール説明文への隠蔽指示でAIエージェントが機密データを漏洩・エンタープライズAIエージェント導入組織にガバナンス見直し要請・バーストカウント4件（threshold_met）・本編採用（AI-2026-06-30-002） |
| 282 iOS AIアプリ LLM APIキー漏洩調査 | C4 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News 2026-06-30・Wake Forest大学研究・LLMKeyLensツールでiOS AIアプリ444本中282本（64%）がLLM API認証情報を漏洩・146本（52%）完全悪用可能・通報後3ヶ月で28%のみ修正・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-30-003） |
| Phantom Squatting: LLMハルシネーションドメインを悪用したフィッシング・サプライチェーン攻撃 | A1 | 2026-07-02 | 継続監視 | 2026-07-02 | YES | Unit 42/The Hacker News/Dark Reading 2026-07-01〜02・913ブランド68万5,339プロンプト分析・220万URL特定/1万3,229件悪用済み・実例2件でカード情報等窃取確認・フィッシングキット「Montana Empire」・バーストカウント6件（burst_exceeded）・本編採用（AI-2026-07-02-001） |
| DuneSlide: Cursor IDEゼロクリック・プロンプトインジェクション経由サンドボックス回避RCE（CVE-2026-50548/CVE-2026-50549） | B1 | 2026-07-01 | 継続監視 | 2026-07-02 | YES | Cato AI Labs/The Hacker News/CSO Online 2026-07-01〜02・CVSS9.8×2・run_terminal_cmd working_directory検証不備＋シンボリックリンク解決フォールバック不備・修正済み(Cursor 3.0)・実悪用未確認・バーストカウント6件（burst_exceeded）・本編採用（AI-2026-07-02-002） |
| DeepSeek生成のブラウザ単体型ランサムウェア技術（InfernoGrabber v9.0） | A3 | 2026-07-02 | 継続監視 | 2026-07-02 | YES | Check Point Research/The Hacker News/BankInfoSecurity 2026-07-01〜02・DeepSeek(LLM)生成・Chromium File System Access API悪用・root権限不要のファイル暗号化/上書き・Discordトークン窃取等併載・実被害未確認（VirusTotal検体解析段階）・バーストカウント5件（threshold_met）・参考B採用（AI-2026-07-02-003） |
| JadePuffer: Langflow/Nacos脆弱性起点のエージェント型AI自律型ランサムウェア攻撃（CVE-2025-3248） | A4 | 2026-07-04 | 継続監視 | 2026-07-04 | YES | SecurityWeek/Sysdig/The Register/The Hacker News 2026-07-02〜03・エンドツーエンドで完結する初のエージェント型ランサムウェア事例・Langflow CVE-2025-3248(未認証コード実行)起点・Nacos CVE-2021-29441悪用で横展開・Nacos設定1,342件暗号化破壊・被害組織名/金額非公開・バーストカウント4件（threshold_met）・本編採用（AI-2026-07-04-001） |
