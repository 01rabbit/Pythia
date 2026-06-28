# pipeline-ai-1.md — AI攻撃インテリジェンス: 調査ルール・カテゴリ定義

## 概要

このパイプラインは「AIが関係する攻撃」を専門的に追跡する。
CVE/APTパイプラインと同じ日次24時間窓で実行し、レポートの別セクション（【AI攻撃動向】）として出力する。

### 調査窓とノイズフィルタ
- 調査対象期間: CVE/APTと同じ24時間窓（Step 0 で確定した窓を使用）
- ノイズフィルタ: Temporal Burst Filtering を必ず適用する
  - 鮮度チェック: 24時間窓内に新しい記事・アドバイザリ・論文があること
  - 持続性チェック: 48時間以内に3件以上の独立ソース（同一ベンダー系列は1件と数える）が確認できること
  - 3件未満の単発シグナルは「低優先度」フラグを付け、参考B以下に留める（本編昇格不可）
  - 6件以上は「バースト検出閾値超過」として【24時間以内の変化】欄に1行添える
- AI攻撃の既報管理: reported-ai-attacks.md で重複チェックを行い、変化のないエントリは除外する

AI攻撃は3カテゴリに分類する:
- カテゴリA: AI武器化（AI as Weapon） — AIを攻撃ツールとして使う
- カテゴリB: AI攻撃対象（Attacks on AI） — AIシステム自体を攻撃する
- カテゴリC: AIインフラ攻撃（AI Infrastructure Attacks） — AIの基盤・ライブラリを攻撃する

---

## カテゴリ定義

### カテゴリA: AI武器化（AI as Weapon）

AIを攻撃側のツールとして活用する手口。

| サブカテゴリ | 内容 |
|------------|------|
| A1 | AI生成フィッシング・スピアフィッシング（LLMによる標的別文章生成） |
| A2 | DeepFake詐欺（音声クローン・動画・画像合成によるBEC・CEO詐欺・採用詐欺） |
| A3 | AI支援マルウェア生成・難読化・多形態化（WormGPT・EscapeGPT等ジェイルブレイク済みモデル） |
| A4 | Agentic AI悪用（AIエージェントに悪意ある操作を実行させる・Agentjacking等） |
| A5 | AI自動化OSINT・偵察・クレデンシャルスタッフィング高速化 |
| A6 | AI Worm（自己複製型プロンプトによるLLMシステム間伝播） |

### カテゴリB: AI攻撃対象（Attacks on AI）

AIシステムそのものを操作・破壊・情報窃取する手口。

| サブカテゴリ | 内容 |
|------------|------|
| B1 | プロンプトインジェクション（直接・間接・マルチモーダル画像埋め込み型） |
| B2 | RAGポイズニング・ベクターDB汚染・False RAG Entry Injection |
| B3 | ジェイルブレイク・モデル安全装置回避 |
| B4 | モデル反転攻撃・訓練データ抽出・メンバーシップ推論攻撃 |
| B5 | 敵対的サンプル（Adversarial Examples）による誤分類誘発 |
| B6 | データ・モデルポイズニング（学習データ汚染・バックドア埋め込み） |

### カテゴリC: AIインフラ攻撃（AI Infrastructure Attacks）

AIの基盤ソフトウェア・サービス・サプライチェーンを攻撃する手口。

| サブカテゴリ | 内容 |
|------------|------|
| C1 | AIプラットフォームCVE（Ollama・LangChain・LiteLLM・LlamaIndex・MLflow等） |
| C2 | MLサプライチェーン攻撃（Hugging Face上の悪意あるモデル重み・Pickleファイル） |
| C3 | MCPサーバ・エージェント統合基盤の悪用（Agentjacking: Sentryへの不正注入等） |
| C4 | AIモデルホスティング・レジストリへの不正アクセス・トークン漏洩 |
| C5 | AI SaaS OAuth乗っ取り・権限昇格・過剰権限の悪用 |
| C6 | PyPI・npm上のAI関連パッケージへのバックドア埋め込み（サプライチェーン） |

---

## 追跡フレームワーク（ATLAS ID付与）

各エントリにMITRE ATLAS IDを付与する:
- MITRE ATLAS: https://atlas.mitre.org （16タクティクス・84テクニック・32ミティゲーション）
- OWASP LLM Top 10 (2026): https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Top 10 for Agentic Applications (2026): https://owasp.org/www-project-top-10-for-ai-agentic-systems/
- NIST AI RMF (AI 100-1): https://www.nist.gov/artificial-intelligence

MITRE ATLASのID形式: AML.Txxxx（テクニック）、AML.Mxxxx（ミティゲーション）

---

## 調査ソース（優先順）

### 一次ソース（研究・フレームワーク機関）
| ソース | URL | 用途 |
|--------|-----|------|
| MITRE ATLAS | atlas.mitre.org | テクニック・ケーススタディ追跡 |
| OWASP GenAI Security Project | owasp.org/www-project-top-10-for-large-language-model-applications | LLM/Agentic脆弱性 |
| arXiv cs.CR（AIセキュリティ論文） | arxiv.org/list/cs.CR/recent | 研究最前線 |
| AI Incident Database | incidentdatabase.ai | 実インシデント記録 |
| NIST AI RMF | nist.gov/artificial-intelligence | リスク分類 |
| International AI Safety Report | arxiv.org/abs/2602.21012 | 年次リスク評価 |

### 二次ソース（ベンダー・セキュリティ専門）
| ソース | URL | 用途 |
|--------|-----|------|
| HiddenLayer Research | hiddenlayer.com/research | MLシステム攻撃 |
| Adversa AI Blog | adversa.ai/blog | Adversarial ML |
| Trail of Bits Blog | blog.trailofbits.com | AIセキュリティ監査 |
| Prompt Security Blog | prompt.security/blog | プロンプトインジェクション |
| Embrace The Red | embracethered.com/blog | LLM攻撃デモ |
| LLM Security Newsletter | llmsecurity.net | 週次まとめ |
| Google Project Zero | googleprojectzero.blogspot.com | AIシステム脆弱性 |
| Anthropic / OpenAI Security | anthropic.com, openai.com | モデル提供元のアドバイザリ |

### 三次ソース（一般セキュリティニュース）
| ソース | URL | 用途 |
|--------|-----|------|
| The Hacker News (AI tag) | thehackernews.com/search/label/artificial%20intelligence | ニュース |
| SecurityWeek (AI/ML) | securityweek.com | 業界報道 |
| Help Net Security | helpnetsecurity.com | 調査レポート |
| BleepingComputer | bleepingcomputer.com | 具体的インシデント |
| Dark Reading | darkreading.com | AI脅威分析 |
| Infosecurity Magazine | infosecurity-magazine.com | 統計・調査 |

---

## 採用条件 P〜Z（期間内に1つ以上確認できること）

| 記号 | 条件 |
|------|------|
| P | AI攻撃手法の新規研究発表・論文公開（実証あり） |
| Q | 実際のインシデント・被害報告（組織名・金額等の具体情報） |
| R | AIセキュリティCVEの新規公開・KEV登録 |
| S | AIプラットフォーム・ライブラリの脆弱性発見・アドバイザリ |
| T | 政府機関・規制当局によるAIセキュリティ警告・ガイダンス発行 |
| U | 業界調査・統計レポートによる脅威の定量化（新規データ） |
| V | 新規ジェイルブレイク手法・プロンプトインジェクション実証公開 |
| W | AIサプライチェーン汚染の確認（悪意ある重み・パッケージ） |
| X | 脅威アクターによるAIツール（WormGPT等）の悪用確認・新規ツール公開 |
| Y | MITRE ATLAS新規テクニック・ケーススタディ追加 |

---

## 除外ルール

- 期間内に P〜Y が確認できない場合は除外
- 理論的なリスク提起のみで実証・被害なし → 低優先度フラグ
- 一般的なフィッシング・マルウェアでAIが補助的に使われたと推測されるだけのもの → 低優先度フラグ（明確なAI起因が確認できるもののみ採用）
- 既報のインシデント・脆弱性で期間内に変化なし → 除外

---

## 各エントリに付与するメタデータ

- タイトル（インシデント名・研究名・CVE等）
- カテゴリ: A〜C / サブカテゴリ番号
- 採用契機: P〜Y の該当記号
- MITRE ATLAS ID（判明分）
- OWASP LLM Top 10 / Agentic Top 10 の該当項目（判明分）
- 対象: 被害者・標的（組織種別・地域）
- 攻撃者: 脅威アクター種別（国家系・犯罪組織・研究者実証等）
- 被害規模: 金額・件数・露出組織数等（判明分）
- 期間内の変化: いつ・どのソースで・何が確認されたか
- 優先度タグ: 必須 / 高 / 中 / 低優先度
- 監視SPL候補: 検知に使えるSIEMログソースと検知ポイントのヒント
- 関連URL（全件保持）

---

## 並び順（次ステップへの引き渡し順）

1. 実インシデント・確認済み被害（Q）
2. CVE登録 / 実証済み攻撃手法（R・P）
3. AIプラットフォーム脆弱性（S）
4. 脅威アクターのAIツール悪用（X）
5. 政府警告・大規模調査レポート（T・U）
6. 低優先度フラグ付き（参考留め候補）
