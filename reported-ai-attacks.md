# reported-ai-attacks.md — 既報AI攻撃インシデントリスト

このファイルはAI攻撃インテリジェンスタスク実行後に状態遷移ベースで更新されます。
同一インシデントは再掲せず、`インシデント名 / CVE等` をキーに `最終状態` と `最終更新日` を更新してください。

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
| Djinn Stealer: CVE-2026-48558経由AI開発者認証情報・MCPコンフィグ窃取 | C3 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | BleepingComputer/Horizon3.ai/HelpNetSecurity 2026-06-29・CVE-2026-48558（SimpleHelp CVSS 10.0 OIDC認証バイパス）経由・Claude/Gemini/Codex/Cline/OpenCode/Kilo等AI開発者設定・MCPコンフィグ・SSH/クラウド/Docker/Terraform認証情報窃取・バーストカウント3件（threshold_met）・本編採用（AI-2026-06-29-001） |
| LiteLLM CVE-2026-42271 SSRF（AI ゲートウェイ内部偵察） | C1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | GitHub Advisory/NIST/SecurityWeek 2026-06-28・CVSS 9.1・CWE-918 SSRF・LiteLLM 1.42.0以下・1.43.0パッチリリース・PoC公開・内部ネットワーク偵察可能・バーストカウント3件（threshold_met）・参考B採用（AI-2026-06-29-002） |
| Miasma AI ワーム（AI インフラ間自己増殖型マルウェア） | C6 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Wiz Research/DarkReading 2026-06-28・AI インフラ間を自己増殖・MCP サーバー/Ollama インスタンス/Jupyter ノートブックを連鎖侵害・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-003） |
| Gemini 搭載 SMiShing キャンペーン（AI 生成 SMS フィッシング個別最適化） | A1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Zscaler/ThreatPost 2026-06-28・Gemini API 悪用・個人属性ベースの高精度 SMS フィッシング生成・金融/EC ユーザー標的・バーストカウント2件（below_threshold）・参考A採用（AI-2026-06-29-004） |
| Claude Code GitHub Actions プロンプトインジェクション（CI/CD パイプライン乗っ取り） | B1 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Wiz Research/HelpNetSecurity 2026-06-28・GitHub PR コメント経由プロンプトインジェクション・Claude Code が CI/CD 内で悪意ある指示を実行・シークレット漏洩/コード改ざんリスク・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-005） |
| OpenClaw Pinchy: オープンソース LLM 自律型ペネトレーションフレームワーク | A4 | 2026-06-29 | 継続監視 | 2026-06-29 | YES | Unit 42/DarkReading 2026-06-29・Ollama/llama.cpp 自律 AI エージェントを攻撃推論エンジンに悪用・偵察→脆弱性特定→エクスプロイト選択まで自動化・犯罪グループによる実戦運用確認・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-29-006） |
| GuardFall: オープンソースAIコーディングエージェントのbashシェルインジェクション | B1 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News/SecurityWeek 2026-06-30・Adversa AI研究・11種中10種のオープンソースAIコーディング/コンピュータ操作エージェントでシェルインジェクション実証成功（Continueのみ防御）・bashコマンド書き換えによるブロックリスト回避・バーストカウント3件（threshold_met）・本編採用（AI-2026-06-30-001） |
| Microsoft MCPツール説明文汚染（Tool Poisoning）警告 | B1 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News 2026-06-30・Microsoft公式セキュリティアドバイザリ・MCPツール説明文への隠蔽指示でAIエージェントが機密データを漏洩・エンタープライズAIエージェント導入組織にガバナンス見直し要請・バーストカウント4件（threshold_met）・本編採用（AI-2026-06-30-002） |
| 282 iOS AIアプリ LLM APIキー漏洩調査 | C4 | 2026-06-30 | 継続監視 | 2026-06-30 | YES | The Hacker News 2026-06-30・Wake Forest大学研究・LLMKeyLensツールでiOS AIアプリ444本中282本（64%）がLLM API認証情報を漏洩・146本（52%）完全悪用可能・通報後3ヶ月で28%のみ修正・バーストカウント2件（below_threshold）・参考B採用（AI-2026-06-30-003） |
