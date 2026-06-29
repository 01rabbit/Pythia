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
