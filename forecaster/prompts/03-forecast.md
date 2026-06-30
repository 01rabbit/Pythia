# prompts/03-forecast.md — ステージ03: 予報生成

## あなたの役割

本日の observations・ベースライン・グループプロファイルを統合し、
定量的根拠に基づいたサイバー脅威予報を生成する。

このステージは既存パイプラインの `pipeline-3-weighting.md` の【攻撃予報（48〜72時間）】セクションを
**強化**するものであり、**置き換えではない**。
生成した予報は `forecaster/forecasts/daily/YYYY-MM-DD.md` に出力する。
既存パイプラインの outputs/ へのコピーは行わない（pipeline-3-weighting.md 側から参照するのみ）。

---

## 入力

1. `forecaster/observations/YYYY/MM/YYYY-MM-DD.json`（当日）
2. `forecaster/baseline/technique-freq.json`
3. `forecaster/baseline/group-activity.json`
4. `forecaster/knowledge/attack-groups.json`
5. `forecaster/knowledge/technique-chains.json`
6. `forecaster/knowledge/poc-exploitation-criteria.json`（T3採用のPoC難易度足切り）
7. `forecaster/knowledge/incident-visibility-timelines.json`（M2 検証窓割当の根拠）
8. 当日レポート JSON の CVE エントリの `epss`（EPSS スコア/パーセンタイル）・`status.kev_registered`（M3 確度アンカー用）

---

## 判定ロジック（4ステップ）

### Step A': KEV登録 + 実確認イベント起点

当日 observations に `exploitation_stage: "kev_listed"` または
`exploitation_stage: "active_exploitation"` を含む CVE があり、かつ以下のいずれか1つが
同日 observations または当日ニュースソースで実確認されている場合のみ予報候補とする。

- 対象製品の新規スキャン増加・悪用試行がCERT/SIEMレポートで確認されている
- 新規C2インフラ・IOC（IP / ドメイン / ハッシュ）が公開されている
- PoC公開後48時間以内の攻撃加速報告が確認されている

`KEV` 単体の場合は予報を生成しない。observation の `tags` に `kev_watch` を追記し、
翌日以降の観測を待つ。

ベースライン期間が14日未満でも、上記の実確認条件を満たす場合は予報候補として扱う。

KEV起点予報テンプレート:

- Evidence: `CISA KEV登録日: YYYY-MM-DD + 実確認の内容と出典`
- 的中判定条件: `対象製品への新規スキャン・侵害試行・悪用PoC公開のいずれか（72h以内）`
- 確度上限: `中`
- 注記: `（推測）KEV登録後の攻撃加速は過去パターン。個別環境での発生は確認されていない。` を必ず付与

### Step A: Technique 逸脱スコアの算出

当日 observations の各 Technique 出現件数をカウントし、baseline と比較する。

```
逸脱 σ = (当日件数 - mean_per_day) / stddev
```

| σ | 警戒レベル |
|---|-----------|
| σ < 1.0 | 平常 |
| 1.0 ≤ σ < 2.0 | 注意（caution） |
| σ ≥ 2.0 | 警戒（warning） |

baseline が未確立（stddev = 0 or null）の Technique は「ベースライン未確立」として別枠で報告する。

### Step B: グループ活性化の判定

`group-activity.json` の `sigma_deviation` を参照する。

| 条件 | 判定 |
|------|------|
| sigma_deviation ≥ 2.0 | 活性化（警戒） |
| 1.0 ≤ sigma_deviation < 2.0 | やや活性化（注意） |
| last_seen が7日以内かつ sigma_deviation 不明 | 直近観測あり（要注視） |

### Step C: 次段階TTP予測

活性化グループについて `attack-groups.json` の `typical_tactics_order` を参照する。

1. 当日の observations でそのグループが観測された最後の tactic を特定する。
2. `technique-chains.json` の `transition_matrix` から次段階への遷移確率を参照する。
3. 遷移確率 ≥ 0.60 のものを予報候補とし、`attack-groups.json` の `common_techniques` から
   次段階の代表 Technique を推定する。

この推定は「（推測）」として必ず明記すること。

### Step C': 認証情報・トークン連鎖予報

当日 observations に以下のいずれかが観測された場合は、認証情報・トークンの二次利用を
48〜72時間の予報候補として別枠評価してよい。

- `T1555`（Credentials from Password Stores）を含む observation
- `T1528`（Steal Application Access Token）を含む observation
- `T1539`（Steal Web Session Cookie）を含む observation
- 大規模認証情報漏えい・フィッシングキャンペーン検出の observation

連鎖予報テンプレート:

- Evidence: `流出 / 窃取イベントの observation_id`
- 予報内容: `窃取された認証情報・トークンが48〜72時間以内に再利用される可能性がある`
- 的中判定条件: `クレデンシャルスタッフィング攻撃増加・横展開・別組織での不正ログイン観測`
- 確度上限: `中`
- 注記: `（推測）認証情報の二次利用は過去事例に基づく経験則。パスワード変更後もセッショントークンが残存する場合あり。` を必ず付与
- 関連Technique: `T1078`（Valid Accounts）、`T1550`（Use Alternate Authentication Material）を参考として記録してよい
  ただし推測であり、根拠あるTechnique紐付けとしては記録しない

法執行・摘発に関する observation がある場合も、流出資産の継続利用予報は維持してよい。
C2摘発 observation には「摘発はリスク低下であって終息ではない」と注記する。

### Step D: 予報の絞り込みと Tier 判定

`pipeline-forecast-verification.md` のルール（M1〜M4 含む）に完全準拠する。

- 最大2件
- T1 > T2（σ≥1.0）> T2（KEV+実確認）> T3 の優先順
- 同Tier内ではKEV起点を優先
- T3 は原則「確度: 中」
- ベースライン逸脱の定量証拠があれば T2 への昇格根拠として使用可能

**M1 観測可能性ゲート（発行前必須）**: 各予報の的中条件を観測出口クラス E1〜E4（KEV初回追加 / 新規IOC公開 / CERT初回勧告 / PoC公開）の一次・二値イベントに紐付ける。「国内被害報道」「KEV再登録」「悪用拡大（曖昧）」を的にする予報は発行せず注意点1行へ格下げ。

**M3 EPSS+SSVC 確度アンカー**: 確度=高は「KEV登録 AND EPSS percentile≥0.95 AND SSVC=Act/Attend」を満たす場合のみ。SSVC `Automatable=no`（ASLR回避・認証・多段要）は確度=高から自動降格。EPSSは確度裏取りのみに使い72h的中条件に流用しない。

**M2 検証窓**: 外部報道依存の主題（漏洩→国内被害等）は `forecast_class: slow_7d`（7日窓）へ割り当て。72h的中率の分母に混入させない。割当判断は `incident-visibility-timelines.json` の median_days_to_external_report に従う（3日超は fast_72h で発行しない）。ベンダー追随IOCの的中条件への扱いは下記「T2 E2追随ベンダー除外（暫定）」に従う。

**T3足切り**: T3予報候補は `poc-exploitation-criteria.json` の required を全て満たし disqualifying を満たさない場合のみ採用。1つでも欠ければ本編・参考Aの注意点1行へ格下げ（教訓10）。

**low-visibility遷移**: `technique-chains.json` の `low_visibility_chains`（漏洩→BEC・BYOVD回避更新）に該当する主題は外部報道を的中条件にせず slow_7d または先回り監視へ。

**T2 E2追随ベンダー除外（暫定）**: T2予報のE2（新規IOC公開）的中判定に「競合（一次ソース以外の）ベンダーの72h追随IOC公開」を使用しない。代替: 一次ソース自身の続報・追加IOC更新、またはKEV初回追加(E1)。追随速度の実測は `vendor-ioc-followup-timelines.json` に蓄積し `pct_within_72h≥50%` を確認できるまでE2的中条件に採用しない（Issue #19・人間レビュー前の暫定対応）。

**M4 KEVスナップショット**: 各予報に発行時点のKEV状態（dateAdded / ランサムフラグ / 参照セット）を `kev_snapshot` として記録し、検証時に再登録（変化なし）を非的中判別できるようにする。

---

## 出力ファイル形式

`forecaster/forecasts/daily/YYYY-MM-DD.md` に以下の形式で保存する。

```
# サイバー脅威予報 YYYY-MM-DD

生成時刻: YYYY-MM-DD HH:MM JST

## 警戒レベル: [平常 / 注意 / 警戒]

## 事実（本日の観測サマリー）
観測件数: N件
Technique 逸脱上位:
  - T1566 (initial-access): +2.3σ [警戒] — 当日X件 / 平常平均Y.Y件/日
  - T1059 (execution): +1.2σ [注意]
活性化グループ:
  - Lazarus Group: 当週X件 / 週平常平均Y.Y件 (+Z.Zσ) [警戒]

## 分析
[ベースライン逸脱の解釈。事実として確認できたことのみ記述。]

## 予測
[Tier・確度・根拠・推定部分を明記。推測には「（推測）」を付ける。]

・予報1: [タイトル]
Tier: X
確度: 高/中（M3: 確度=高はEPSS%ile≥0.95 AND KEV AND SSVC=Act/Attend。Automatable=noは自動降格）
観測出口クラス: E1/E2/E3/E4（M1）
検証窓: fast_72h / slow_7d（M2・slow_7dは割当根拠1行）
Evidence: [具体的なソース名と日付]
過去パターン: [類似事象の実績]
確度アンカー: [EPSS percentile / KEV状態 / SSVC決定 / Automatable / EPSS算出日]（M3）
推定部分: [推論箇所の明示]（推測）
先回り監視: [最初に現れるシグナル]
的中判定: [観測出口クラスE1〜E4の一次・二値イベントのみ。「国内被害報道」禁止（M1・原則B）]
KEVスナップショット: [dateAdded / ランサムフラグ / 参照セット]（M4・E1予報時）

## 推奨アクション
[予測に対応する防御行動]

## ベースライン未確立の観測（参考）
[stddev=0 または baseline 未収録の Technique 出現リスト]
```

---

## 重要制約

- 事実（observations）と推測（次段階予測）を絶対に混在させない。
- `attack-groups.json` に登録されていないグループの次段階予測は行わない。
- 地政学シグナル単体での予報生成は禁止する。
  `geopolitical_signal` を含む observation に加え、同日の独立した技術的観測
  （IOC公開 / 新規TTP報告 / CERT勧告のいずれか）が揃った場合のみ予報候補とする。
- ベースライン期間が14日未満の場合、定量逸脱スコアを予報の根拠として使わない。
  その場合は既存パイプライン（pipeline-forecast-verification.md）のルールのみで予報を作成する。
- `pipeline-forecast-verification.md` の「確度: 高」適用条件・絞り込みルール・的中判定条件の記載義務を必ず遵守する。
