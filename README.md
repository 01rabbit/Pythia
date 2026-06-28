# PYTHIA — サイバー戦術予報士

> 神託は、あなたの観測から生まれる。

PYTHIA は、サイバー脅威の「天気予報士」です。
日々の観測データから脅威の傾向を読み取り、**確度付きのサイバー攻撃予報**を生成し、
その予報を実績と突き合わせる**検証ループ**で精度を継続的に改善していきます。

デルフォイの神殿でアポロンの神託を告げたピュティアは、未来を断言せず、
観測と解釈を組み合わせた確率的な神託を告げました。
不確実な未来を「確度付きの予測」として語る——それがこのツールの本質です。

---

## このリポジトリの主役は「予報」である

```
                    ┌─────────────────────────────────────┐
                    │   PYTHIA = サイバー攻撃予報の生成     │  ← 目的（主役）
                    └─────────────────────────────────────┘
                                     ▲
                          予報の精度を高めるために
                                     │
        ┌────────────────────────────┴────────────────────────────┐
        │                                                          │
   日々の観測データ供給                                    検証ループ
   （日次セキュリティ                                  （予報 × 実績の突合）
     インテリジェンス収集）                                      │
        │                                                          │
   CVE / APT / AI攻撃 / トレンド                          的中率の記録と
   を収集・正規化して                                     knowledge の補正
   Pythia の「観測」にする                                        │
        └──────────────────────────────────────────────────────────┘
```

日次のセキュリティインテリジェンス収集（CVE・APT・AI攻撃・トレンド）は、
それ自体が目的ではなく、**Pythia に予報の材料となる観測データを供給するための作業**です。
収集した情報は ATT&CK 正規化を経て observation となり、ベースラインと突き合わされ、予報の根拠になります。

**検証ループが回り始めた日が、Pythia の誕生日です。**

---

## 設計思想（3つの核心原則）

1. **構造化が先、量は後** — 収集量ではなく、正規化スキーマと検証ループが精度を決める。
2. **Git が記憶装置** — Claude はセッションをまたいで記憶しない。すべての観測・予報・検証をコミットすることで、リポジトリの履歴が Pythia の長期記憶になる。
3. **検証ループが精度を生む** — 「予報 → 実績突合 → 補正 → 再予報」のループが回ることが精度の源泉。蓄積量は必要条件ではない。

---

## Pythia の中核：4ステージ予報パイプライン

予報生成の心臓部は `forecaster/` にある。

```
[日次収集] 観測材料の取得（CVE/APT/AI攻撃/トレンド）
    ↓
[01 正規化]   ATT&CK スキーマに沿って observation 化
    ↓ forecaster/observations/ にコミット
[02 ベースライン] 平常状態の統計を更新（TTP頻度・グループ活性度）
    ↓ forecaster/baseline/ にコミット
[03 予報生成]  ベースライン逸脱と knowledge から確度付き予報を生成
    ↓ forecaster/forecasts/daily/ にコミット
[04 検証]      過去の予報を実観測と突合し的中率を記録、knowledge補正を提案
    ↓ forecaster/verification/ にコミット + 補正提案を Issue 化
    ↓
[人間レビュー] 補正提案をマージ → knowledge/ が育つ → 次サイクルで精度が上がる
```

| ステージ | 実行タイミング | 出力 | プロンプト |
|----------|--------------|------|-----------|
| 01 正規化 | 日次（収集後） | `forecaster/observations/YYYY/MM/YYYY-MM-DD.json` | `forecaster/prompts/01-normalize.md` |
| 02 ベースライン | 日次（01後） | `forecaster/baseline/*.json` | `forecaster/prompts/02-baseline.md` |
| 03 予報生成 | 日次（02後） | `forecaster/forecasts/daily/YYYY-MM-DD.md` | `forecaster/prompts/03-forecast.md` |
| 04 検証 | 週2回（火・木 12:00 JST） | `forecaster/verification/YYYY-MM.json` | `forecaster/prompts/04-verify.md` |

> Pythia の構造・育て方の詳細は [`forecaster/README.md`](forecaster/README.md) を参照。

---

## 観測データを供給する：日次セキュリティインテリジェンス収集

Pythia の予報精度は観測データの質に依存する。
そのため、毎日 CVE・APT 活動・AI 攻撃動向・SOC 推奨情報を収集・重みづけし、
正規化の入力となる構造化レポートを生成する。

```
Step 0  時刻確認・調査期間確定（前日 07:00 JST 〜 当日 07:00 JST）

Step 1  情報収集（3トラック並行）
         ├─ Step 1:  CVE調査    — NVD / CISA KEV / GitHub Advisory / ベンダー
         ├─ Step 1b: APT活動    — Mandiant / MSTIC / CrowdStrike / Unit 42 / CISA合同勧告
         └─ Step 1c: AI攻撃     — MITRE ATLAS / OWASP GenAI / arXiv / AI Incident DB

Step 2  動向収集
         ├─ 英語ソース: BleepingComputer / The Hacker News / SecurityWeek 等
         └─ 日本語ソース（必須）: Security NEXT / JPCERT/CC / IPA / ScanNetSecurity 等

Step 3  重みづけ・スコアリング・出力（security-report.json + 5種テキスト）

Step 3.5  予報士システム連携 — 上記出力を 01 正規化 → 02 ベースライン → 03 予報 に投入

Step 4  ファイル更新・コミット（main へ直接コミット "daily report: YYYY-MM-DD"）
```

収集レポートの構成（Section 1〜4）と出力ファイルは下記の通り。

| ファイル | 内容 | 主な用途 |
|---|---|---|
| `security-report.json` | Section 1〜4 全データ（構造化） | 正規化の入力・AI分析・機械処理 |
| `security-report.txt` | Section 1〜4 完全版 | 日次レビュー・共有 |
| `security-report-cve.txt` | Section 3: 製品別CVE | CVE担当 |
| `security-report-zeroday-trends.txt` | Section 2: ゼロデイ・トレンド | トレンド担当 |
| `security-report-ai.txt` | Section 1: AI攻撃動向 | AI担当 |
| `security-report-soc.txt` | Section 4: SOC推奨情報 | SOC担当 |

テキストファイルはすべてプレーンテキスト（Markdown記法なし）。

---

## 自動実行

### Claude Code Routines（LLM処理の本体）

```
Claude Code Routines（クラウド）
  └─ 毎日 07:00 JST に自動起動
       └─ SKILL.md を実行（収集 Step 0〜4 + 予報 Step 3.5）
            └─ outputs/ + forecaster/ に保存 → main へ直接コミット
  └─ 火曜・木曜 12:00 JST
       └─ 04 検証を実行 → 的中率記録・knowledge補正提案
```

手動実行は Routines 画面の「Run」をクリック。

### GitHub Actions（LLMを使わない補助自動化）

LLM 処理（分析・予報・コミット）はすべて Routines が行う。
GitHub Actions は外部 API キー不要の補助タスクのみを担当する。

| ワークフロー | タイミング | 役割 |
|---|---|---|
| `.github/workflows/daily-pipeline.yml` | 06:00 JST（Routines の1時間前） | RSSフィード収集（Python）→ コミット |
| `.github/workflows/weekly-verify.yml` | 火・木 11:55 JST | 検証タスクの Issue 作成（リマインド） |

`GITHUB_TOKEN`（自動付与）のみで動作する。`NVD_API_KEY` は任意（レート制限緩和用）。

---

## リポジトリ構成

```
config.yml                          ← Pythia の個性を定義（スコープ・優先事項・フェーズ）
CLAUDE.md                           ← Claude Code への最上位指示書（Pythia の人格・行動原則）
SKILL.md                            ← 日次パイプラインの実体（Routines にファイルパス指定で登録）

forecaster/                         ← ★Pythia の中核：予報エンジン★
  README.md                         ← Pythia の育て方・Phaseロードマップ
  phase1-config.json                ← 現フェーズ設定（フォーカス: Lazarus Group）
  schema/observation.schema.json    ← ATT&CK 正規化スキーマ
  knowledge/                        ← 空で起動。検証ループで育てる知識ベース
  observations/YYYY/MM/             ← 正規化済み観測データ（日次蓄積）
  baseline/                         ← TTP出現頻度・グループ活性度の平常統計
  forecasts/daily/                  ← 日次サイバー脅威予報
  verification/                     ← 予報 × 実績の突合記録（月次JSON）
  prompts/01〜04.md                 ← 4ステージのプロンプト

収集ルール（観測データ供給）:
  pipeline-1-cve.md                 ← CVE調査（監視対象製品リスト含む）
  pipeline-1b-apt.md                ← APT活動調査
  pipeline-ai-1.md                  ← AI攻撃調査
  pipeline-2-trends.md              ← 動向収集
  pipeline-3-weighting.md           ← CVE/APT 重みづけ・出力テンプレート
  pipeline-ai-2.md                  ← AI攻撃 重みづけ・出力テンプレート
  pipeline-soc-recommend.md         ← SOC推奨情報 収集・出力ルール
  pipeline-report-modes.md          ← 出力ファイル定義・ゼロデイ特報テンプレート
  pipeline-output-schema.md         ← security-report.json スキーマ定義
  pipeline-forecast-verification.md ← 攻撃予報 精度検証ルール

reported-cves.md / reported-apts.md / reported-ai-attacks.md  ← 既報リスト（重複除外用）
outputs/YYYY-MM-DD/                 ← 日次収集レポート（観測材料）
.github/workflows/                  ← 補助自動化（RSS収集・検証リマインド）
```

---

## Phase ロードマップ

| Phase | 期間 | 内容 |
|---|---|---|
| Phase 0 | Week 1 | ディレクトリ・スキーマ確定 ✅ 完了（2026-06-26） |
| **Phase 1** | **Week 2-8** | **Lazarus Group に絞り手動レビュー付きで正規化を検証 → 検証ループ稼働 ← 現在ここ** |
| Phase 2 | Week 8-16 | 業界別・地域別の脅威動向セクション追加 |
| Phase 3 | Week 16-24 | D3FEND 防御連携・推奨防御アクション自動付与 |
| Phase 4 | Week 24+ | 精度統計が揃い、外部発信の素材になる |

### Phase 1 完了条件（的中率の高さは問わない）

- 正規化カバレッジ: 収集情報の 80% 以上に TTP 付与
- ベースライン確立: 90日分の平常分布が算出済み
- 検証ループ稼働: 週次で的中率が記録されている

---

## 運用ルール（厳守事項）

予報の人格・行動原則は [`CLAUDE.md`](CLAUDE.md) に定義。要点は以下。

1. **ハルシネーション厳禁** — ATT&CK Technique の紐付けは確証がある場合のみ。不能なら `techniques: []` + `confidence: low`。
2. **事実と推測の分離** — 観測（事実）と予測（推測）を必ず区別し、推測には「（推測）」を明記。
3. **帰属判断は慎重に** — actor_group は情報源が明示する場合のみ。TTP 類似だけで断定しない。
4. **verified_outcome は検証ステージ（04）のみが書き込む** — 正規化・予報段階では埋めない。
5. **knowledge/ の自動書き換え禁止** — 補正は Issue/PR で提案し、人間レビューを経てマージ。
6. **全変更をコミット** — 観測・予報・検証はすべて Git 履歴に残す。

### 設計上の禁止事項（守らないと精度が下がる方向に育つ）

| 禁止事項 | 理由 |
|---|---|
| knowledge/ を自動書き換えさせる | 誤った補正が蓄積して劣化する |
| verified_outcome を正規化時に埋める | 検証ループが機能しなくなる |
| 的中率を初期から求める | 記録と改善が止まる |
| 帰属不明な情報に actor_group を推測記入 | 知識ベースが汚染される |
| ベースライン未確立のまま予報を本番運用 | 比較基準がなく予報が無意味になる |

---

## コミットルール

| ケース | ブランチ | PR |
|---|---|---|
| 日次予報・収集レポート | main へ直接コミット（`daily report: YYYY-MM-DD`） | 不要 |
| 検証結果 | main へ直接コミット（`verify: forecast accuracy YYYY-MM-DD`） | 不要 |
| knowledge 補正 | Issue/PR で提案 | **必須**（人間レビュー） |

---

## ファイルを編集したい場合

| 目的 | 編集ファイル |
|---|---|
| Pythia のスコープ・優先事項・フェーズ | `config.yml` |
| Pythia の人格・行動原則 | `CLAUDE.md` |
| 正規化ルール | `forecaster/prompts/01-normalize.md` |
| ベースライン算出ロジック | `forecaster/prompts/02-baseline.md` |
| 予報生成ロジック | `forecaster/prompts/03-forecast.md` |
| 検証ロジック | `forecaster/prompts/04-verify.md` |
| 監視対象製品の追加・変更 | `pipeline-1-cve.md` |
| APT追跡対象の変更 | `pipeline-1b-apt.md` |
| 収集の重みづけ基準 | `pipeline-3-weighting.md` |
| 収集の出力テンプレート | `pipeline-3-weighting.md` / `pipeline-ai-2.md` / `pipeline-soc-recommend.md` |
| 収集の JSONスキーマ | `pipeline-output-schema.md` |
| パイプライン実行手順 | `SKILL.md` |
