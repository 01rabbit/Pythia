---
name: daily-security-intel
description: 毎日定時に実行するセキュリティインテリジェンス収集・重みづけ・レポート生成・予報生成タスク
schedule: daily
---

# 日次セキュリティインテリジェンス パイプライン（Pythia 観測〜予報）

> このパイプラインの目的は Pythia の予報生成である。
> Step 1〜3 の情報収集は、Step 3.5 の予報に投入する観測データを供給する作業である。

## 実行前に必ず読むファイル
1. `reported-cves.md` — 既報CVEリスト（重複除外に使用）
2. `reported-apts.md` — 既報APT活動リスト（重複除外に使用）
3. `reported-ai-attacks.md` — 既報AI攻撃リスト（重複除外に使用）
4. `pipeline-1-cve.md` — Step 1 CVE調査ルール（トラックA/B排他的決定木含む・製品リストなし）
5. `pipeline-1b-apt.md` — Step 1b APT活動調査ルール
6. `pipeline-2-trends.md` — Step 2 動向収集ルール
7. `pipeline-3-weighting.md` — Step 3 重みづけ・出力ルール
8. `pipeline-soc-recommend.md` — Step 2b SOC推奨情報収集ルール
9. `pipeline-output-schema.md` — JSONスキーマ定義
10. `pipeline-forecast-verification.md` — 攻撃予報の品質ルール（Step 3 / 3.5 で参照）

## レポート区分（3区分）

本パイプラインは以下の3区分でレポートを構成する:

```
Section 1: AI攻撃動向
  → pipeline-ai-1.md で収集・分類（カテゴリA/B/C）
  → pipeline-ai-2.md で重みづけ・出力

Section 2: ゼロデイ・セキュリティトレンド
  → ゼロデイ特報（CISA KEV・実悪用確認・ゼロデイ報道）
  → APT活動（pipeline-1b-apt.md / pipeline-2-trends.md）
  → 攻撃トレンド（BleepingComputer / THN / SecurityWeek 等）
  → 注目CVE（リスト外製品 — トラック B CVE: CVSS9.0以上・KEV・ゼロデイ等）

Section 3: 製品別CVE
  → pipeline-1-cve.md のトラックA/B排他的決定木（D2）でトラックAに帰属したCVEを対象
  → 製品ごとにCVEを収集・優先度評価
  → 本編 / 参考A（国内）/ 参考B（国際先行）/ 除外サマリー

Section 4: SOC推奨情報
  → pipeline-soc-recommend.md で収集・分類
  → Section 1〜3 に採用されなかったが SOC 運用上把握すべき情報
  → 優先度タグ（高 / 中 / 低）で分類
```

---

## 実行手順

### Step 0: 時刻確認・期間確定
- 現在時刻（JST）を取得する
- 調査対象期間: 実施日前日 07:00 JST 〜 実施日 07:00 JST（固定ウィンドウ）

### Step 0.5: 機械収集データの読み込み（一次入力）
- `security-intel-collector/data/raw/` の当日・前日分 JSON（`news-YYYY-MM-DD.json` / `cves-YYYY-MM-DD.json`、
  無ければ `news-latest.json` / `cves-latest.json`）を読み込み、`items[]` を Step 1〜2 の調査起点とする
- GitHub Actions が3時間おきに自動収集しているため、当日 07:00 JST 時点で複数回分が蓄積されている
- Web 検索は data/raw に無い情報の補完としてのみ使用する（再現性確保のため）
- data/raw が取得できない・空の場合はその旨をレポート meta に記録し、Web 検索へフォールバックする

### Step 1: CVE調査（pipeline-1-cve.md に従う）
- 一次入力: Step 0.5 の `cves-*.json`（NVD API 機械収集済み）。Web 検索は補完のみ
- トラックA/B の定義・帰属判定は pipeline-1-cve.md の「トラックA/B 排他的決定木」に従う
  （本ファイルでは重複定義しない）
- 期間内に採用条件 A〜H の変化が確認できるCVEを収集。`reported-cves.md` と照合し既報除外
- トラックBに帰属した事象には `section_route: trends` タグを付けて Step 2 へ渡す
- 除外基準はフラグ付け（足切りしない）

### Step 1b: APT活動調査（pipeline-1b-apt.md に従う）※Step 1 と並行実行
- Mandiant / MSTIC / CrowdStrike / Unit 42 / CISA合同勧告等を横断検索
- 期間内に P〜W の変化が確認できる活動のみ収集（→ Section 2 へ）
- `reported-apts.md` と照合し、既報かつ変化なしは除外
- Europol / FBI IC3 などの法執行・摘発チェックは日次では行わない（週次検証へ移管）
- 除外基準はフラグ付け（足切りしない）

### Step 1c: AI攻撃調査（pipeline-ai-1.md に従う）※Step 1 / 1b と並行実行
- MITRE ATLAS / OWASP GenAI / arXiv cs.CR / AI Incident Database / HiddenLayer 等を横断検索
  （AI攻撃カテゴリ A: AI武器化 / B: AI攻撃対象 / C: AIインフラ）（→ Section 1 へ）
- `reported-ai-attacks.md` と照合し既報除外
- Temporal Burst Filtering（48時間以内に3件以上の独立ソース）を適用（3件未満 → 低優先度）

### Step 2: 動向収集（pipeline-2-trends.md に従う）
- 一次入力: Step 0.5 の `news-*.json`（RSS 機械収集済み・feeds.json 収録14フィード）。Web 検索は補完のみ
- 英語ソース: BleepingComputer / The Hacker News / SecurityWeek / Mandiant 等
- 日本語ソース（必須）: Security NEXT / JPCERT/CC 注意喚起 / IPA重要情報 / ScanNetSecurity
- APT補完ソース: MSTIC / CrowdStrike / Unit 42 / NISC / 警察庁サイバー警察局
- Step 1 トラック B から渡された `section_route: trends` CVEを受け取り Section 2 へ統合
- 24時間窓内の記事・更新のみ対象、件数制限なし（全件ストック）

### Step 2b: SOC推奨情報収集（pipeline-soc-recommend.md に従う）※Step 2 と並行実行
- 各Stepの調査中にストックした「Section 1〜3 に収まらないが注目すべき情報」を精査
- 採用条件 α〜η を適用し、期間内の変化が確認できるもののみ採用
- JPCERT/CC / IPA / 警察庁 / SANS ISC / Krebs 等を補完確認
- 優先度タグ（高 / 中 / 低）を付与して Step 3 へ渡す

### Step 3: 重みづけ・JSON生成・テキスト変換（pipeline-3-weighting.md・pipeline-ai-2.md に従う）
- **Step 3 実行前に `pipeline-forecast-verification.md` を読むこと**
- Section 3 CVE: 軸1（技術深刻度）× 軸2（実環境影響）で評価、製品単位で集計
- Section 2 CVE（トラック B）: 同上の重みづけを適用しゼロデイ特報・本編・参考A/B へ振り分け
- APT: 軸P（信頼性・活動深刻度）× 軸Q（キャンペーン規模・影響範囲）で評価
- Section 1 AI攻撃: pipeline-ai-2.md の軸X（実証・悪用深刻度）× 軸Y（影響範囲・実害）で評価
- 日本語ソースが確認できたCVEは参考A昇格トリガーを自動適用
- 出力セクション構成:
    [Section 1] AI攻撃動向-本編 / 参考B / 参考A / 週次サマリー / 除外
    [Section 2] ゼロデイ特報 / APT活動-本編 / APT活動-注目動向 / 注目CVE（リスト外） / 攻撃予報 / 除外
    [Section 3] 製品別CVE-本編 / 参考A（国内）/ 参考B（国際先行）/ 除外サマリー
    [Section 4] SOC推奨情報（高優先度 → 中 → 低）

**JSON-first出力手順**:
1. `pipeline-output-schema.md` のスキーマに従い `security-report.json` を生成する
2. JSONの内容を pipeline-3-weighting.md・pipeline-report-modes.md・pipeline-ai-2.md・pipeline-soc-recommend.md のテンプレートに従い5種のプレーンテキストファイルに変換する（Step 4 のファイル一覧参照）

### Step 3.5: 予報士システム — 正規化・ベースライン更新・予報生成（forecaster 統合）

> この Step が Pythia の中核である。Step 3 の出力 JSON が確定してから実行する。
> 既存 collect ロジックには一切手を加えない。
> ★knowledge/ 生成系スクリプト（scripts/build_*.py・scripts/backfill_*.py）は日次ルーチンから
> 実行しない。knowledge/ は自動書き換え禁止であり、これらの再生成は PR 提案+人間レビュー
> 経由のみ。入力ファイルが存在しない場合は参照をスキップし、生成で「修復」しないこと。
> ★この4ステージは2026-06-28に初稼働（observations非空化・ベースライン暫定算出済み）。以後は日次で自動更新する。

1. **正規化（01-normalize.md）**:
   `forecaster/prompts/01-normalize.md` を読み、当日レポート JSON から observation データを生成する。
   出力先: `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`
   現在のモード: **`source_explicit_all`**（phase1-config.json）。情報源が明示する全観測（CVE/APT/AI）に
   techniques/actor_group を付与（R3/R4 の evidence-based 原則を厳守・推測付与禁止）。

2. **ベースライン更新（02-baseline.md）**:
   `forecaster/prompts/02-baseline.md` を読み、observations 全履歴から technique-freq / group-activity を更新する。
   `_baseline_period_days` を記録し有効性フラグ（<14: 警告 / 14-30: 注意 / 30-90: 有効 / ≥90: 安定）を報告する。
   14日未満（暫定値）でも処理は継続するが、定量スコアは予報の根拠に使わない（下記3参照）。

3. **予報生成（03-forecast.md）**:
   `forecaster/prompts/03-forecast.md` を読み、定量的根拠に基づいた予報を生成する。
   出力先: `forecaster/forecasts/daily/YYYY-MM-DD.md`
   ★予報は M1〜M4 ルール（pipeline-forecast-verification.md）に準拠すること:
   - M1 観測可能性ゲート: 的中条件を観測出口クラス E1〜E4（KEV初回追加/新規IOC/CERT勧告/PoC公開）に限定
   - M3 EPSS+SSVC 確度アンカー: 確度=高は KEV AND EPSS%ile≥0.95 AND SSVC=Act/Attend（Step 1 で取得した EPSS を使用）
   - M2 検証窓: 外部報道依存の主題は `forecast_class: slow_7d`（7日窓）へ分離（`incident-visibility-timelines.json` 参照）
   - M4 KEVスナップショット: 発行時KEV状態を記録（検証時の再登録判別用）
   - T3足切り: T3予報候補は `poc-exploitation-criteria.json` の難易度基準（無認証・単一ステップ・ASLR回避不要）を全て満たす場合のみ採用
   ※ベースライン期間が14日未満の場合は定量逸脱スコアを根拠として使用せず、
     `pipeline-forecast-verification.md` のルール（M1〜M4 含む）のみで予報を作成する。

コミット対象に以下を追加する（Step 4 と合わせてコミット）:
- `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`
- `forecaster/baseline/technique-freq.json`
- `forecaster/baseline/group-activity.json`
- `forecaster/forecasts/daily/YYYY-MM-DD.md`
- `forecaster/forecasts/daily/YYYY-MM-DD.json`（予報サイドカー・03-forecast.md 参照）

### Step 4: ファイル更新・保存・コミット
- 本日報告したCVE IDは `reported-cves.md` の該当行を更新する
  フォーマット: `CVE-ID` をキーに `exploitation_stage` / `最終更新日` / `継続監視` / `備考` を更新し、新規のみ追加
- 本日報告したAPT活動は `reported-apts.md` の該当行を更新する
  フォーマット: `活動ID / キャンペーン名` をキーに `最終状態` / `最終更新日` / `継続監視` / `備考` を更新し、新規のみ追加
- 本日報告したAI攻撃は `reported-ai-attacks.md` の該当行を更新する
  フォーマット: `インシデント名 / CVE等` をキーに `最終状態` / `最終更新日` / `継続監視` / `備考` を更新し、新規のみ追加
- 出力先ディレクトリ `outputs/YYYY-MM-DD/` を作成し、以下6ファイルを保存する:
  1. `YYYY-MM-DD-security-report.json` — Section 1〜4 全データ（必須・基本形式）
  2. `YYYY-MM-DD-security-report.txt` — 全セクション完全版（Section 1〜4）
  3. `YYYY-MM-DD-security-report-cve.txt` — Section 3: 製品別CVE
  4. `YYYY-MM-DD-security-report-zeroday-trends.txt` — Section 2: ゼロデイ・トレンド
  5. `YYYY-MM-DD-security-report-ai.txt` — Section 1: AI攻撃動向
  6. `YYYY-MM-DD-security-report-soc.txt` — Section 4: SOC推奨情報
- コミット直前に `python3 scripts/check_reported.py`・`python3 scripts/validate_observations.py`・
  `python3 scripts/validate_forecasts.py`・`python3 scripts/check_knowledge_untouched.py` を
  実行し、違反があれば修正してからコミットする
  （check_knowledge_untouched は knowledge/ の無変更を機械的に確認する。失敗した場合は
  knowledge/ の変更を revert してからコミットし、意図した補正は Issue/PR として提案する）
- 変更ファイル（reported-*.md / outputs/YYYY-MM-DD/ / forecaster/ の Step 3.5 成果物）を
  git add → git commit → git push する。コミットメッセージ: `daily report: YYYY-MM-DD`
- 保存完了後、`security-report.txt`（全セクション完全版）の全文をチャットに表示する

## 出力先
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.json`（基本形式・全セクション）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report.txt`（全セクション完全版）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-cve.txt`（Section 3: 製品別CVE）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-zeroday-trends.txt`（Section 2: ゼロデイ・トレンド）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-ai.txt`（Section 1: AI攻撃動向）
- `outputs/YYYY-MM-DD/YYYY-MM-DD-security-report-soc.txt`（Section 4: SOC推奨情報）
- `reported-cves.md` / `reported-apts.md` / `reported-ai-attacks.md`（追記）
- `forecaster/observations/` `forecaster/baseline/` `forecaster/forecasts/daily/`（Step 3.5）

## 出力形式の原則
- Markdownコードブロック・見出し記号・テーブル記法を使わない
- プレーンテキスト
- 詳細は pipeline-3-weighting.md の「出力形式」セクションを参照
