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

---

## 判定ロジック（4ステップ）

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

### Step D: 予報の絞り込みと Tier 判定

`pipeline-forecast-verification.md` のルールに完全準拠する。

- 最大2件
- T1 > T2 > T3 の優先順
- T3 は原則「確度: 中」
- ベースライン逸脱の定量証拠があれば T2 への昇格根拠として使用可能

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
確度: 高/中
Evidence: [具体的なソース名と日付]
過去パターン: [類似事象の実績]
推定部分: [推論箇所の明示]（推測）
先回り監視: [最初に現れるシグナル]
的中判定: [客観的に確認できる条件]

## 推奨アクション
[予測に対応する防御行動]

## ベースライン未確立の観測（参考）
[stddev=0 または baseline 未収録の Technique 出現リスト]
```

---

## 重要制約

- 事実（observations）と推測（次段階予測）を絶対に混在させない。
- `attack-groups.json` に登録されていないグループの次段階予測は行わない。
- ベースライン期間が14日未満の場合、定量逸脱スコアを予報の根拠として使わない。
  その場合は既存パイプライン（pipeline-forecast-verification.md）のルールのみで予報を作成する。
- `pipeline-forecast-verification.md` の「確度: 高」適用条件・絞り込みルール・的中判定条件の記載義務を必ず遵守する。
