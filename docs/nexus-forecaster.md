# NX-1: 国別 nexus 活動の確認予報（shadow）

Pythia の第4の予報 family。`docs/tactical-forecaster-v3.md` の設計契約
「Actor・標的・インフラ・影響への展開予報は、別 family・別 matching rule・別評価母集団として
追加する。TF-1 の数字を流用しない」に従う。TF-1（脆弱性の悪用段階）とは状態機械・参照率・
被覆記録を共有せず、独立に評価する。

## 何を予報するか

> 発行から H 日以内（H = 3, 7）に、国別 nexus（中国・ロシア・北朝鮮）の `geopolitical_signal` を持つ
> **日次ラン由来の**観測が新たに記録されるか。

- 予報するのは **『確認が記録されるか』** であり、攻撃の発生確率ではない（TF-1 の公開確認確率と同じ）。
  結果は「当該国の関与が語られた」「Pythia がそれを拾い、正規化（R9）が nexus を付けた」の積である
- 対象国は `config.yml` の `neighbor_states.primary`（CN・RU・KP）。韓国・台湾は nexus タグを持たないため対象外
- イラン（`iran_nexus`）は周辺諸国ではないので対象外
- 14 日の地平は置かない。実測した事象の割合が 79〜88% で、基準線との差が見えないため

## matching rule（`nx1-rule-v1`・発行時に固定）

| 項目 | 定義 |
|---|---|
| 窓 | (発行時刻, 発行時刻 + H 日]。観測の `available_at` で数える |
| 事象 | `geopolitical_signal` が当該国の nexus である観測。`machine_backfill*` は除く |
| hit | 窓内、かつ採点時点（as_of）までに利用可能になった観測がある |
| pending | 窓が未満了（右打ち切りを miss にしない） |
| miss | 窓が満了し、窓内の**すべての日次ランが記録されている** |
| not_observed | 窓が満了したが、日次ランの欠測日を含む（『起きなかった』と断定できない） |
| abstained | 台帳で棄権した |

日次ランの欠測日は実測で 145 日中 7 日ある。その日を含む窓を miss にすると、パイプラインの停止を
「何も起きなかった」と誤って学習する。参照率の標本にも入れない。

## モデル（パラメータ調整なし・LLM は確率を書かない）

履歴は `HISTORY_START = 2026-06-29` から（正規化モード `source_explicit_all`（06-28）以降。それ以前は
nexus タグの付け方が異なり、基準率に混ぜられない）。履歴グリッドは各日の 07:30 JST。
窓が満了し被覆済みのグリッド日だけを数える。

| モデル | 役割 | 定義 |
|---|---|---|
| `nx1-climatology-v1` | 基準線 | グリッド日のうち窓内に事象があった割合 `(k+0.5)/(n+1)`（Jeffreys） |
| `nx1-recency-v1` | 挑戦者 | 直近 H 日に事象があったか（0/1）で条件づけた割合。クラスの標本が 14 日未満なら基準線へ後退（`fallback` を記録） |

履歴が 30 日未満なら棄権し、理由（`INSUFFICIENT_HISTORY`）を台帳に残す。
後退・棄権は隠さず台帳に記録する（分母操作の防止）。

## 台帳と検証

- `forecaster/candidates/nexus/YYYY-MM-DD.json`: 発行時にハッシュで凍結（`_ledger_sha256`・各候補の `content_sha256`）。
  発行済みの台帳は書き換えない（再発行は拒否される）
- `scripts/validate_nexus_integrity.py`（fail-closed）: ハッシュ・時刻・構造・公開禁止・根拠の分離に加え、
  **観測を cutoff 時点で読み直して同じ候補が再現できること**を確認する。確率を書き換えてハッシュを付け直した
  台帳は、発行当日（`--date`）の再計算で落ちる。全履歴の再計算（`--all --recompute`）は、履歴の観測が
  欠測日の補完などで正当に変わりうるため**警告**にとどめる
- **追記専用**: 発行済みの台帳は凍結物である。CI が PR の差分で既存の台帳の変更・削除を拒否する
  （追加だけ許可）。ハッシュを付け直した改ざんはファイル内の検査では分からないため、差分で防ぐ
- `scripts/verify_nexus_forecasts.py`: 決定論採点。Brier・log loss・AUC・Brier skill（対 標本平均・対 基準線）・
  較正・被覆。昇格ゲートは `forecaster/config/promotion-gates.json` を TF-1 と共有する
- **独立標本**: 候補の窓は重なり独立ではない。ゲートの `resolved_n`・`positive_events` は **÷H の推定**で数える
- `forecaster/models/nexus-registry.json`: モデル登録簿。`mode: shadow`。昇格は承認記録と、検証出力の
  全ゲート通過を要する（満たさない承認は検証器が拒否する）

## 遡及診断の結果（2026-11-06 時点・昇格の母集団には入れない）

各グリッド日に**その日までの情報だけ**で確率を作り、結果と突き合わせた（ウォークフォワード）。
式は固定で、この結果を見て変更していない。

| 地平 | 行数（独立標本の推定） | 陽性率 | 挑戦者の Brier skill（対 基準線） | 95% 区間 | AUC（挑戦者） |
|---|---|---|---|---|---|
| 72h | 234（約78） | 29% | −0.026 | −0.080 〜 +0.027 | 0.43 |
| 7d | 162（約24） | 54% | −0.012 | −0.063 〜 +0.032 | 0.37 |

- **直近の活動の有無で条件づけても、基準線に勝てていない。** 点推定は負、AUC は 0.5 未満
- ただし区間は 0 をまたぎ、独立標本も小さい。『技能なし』とも『技能あり』とも結論できない
- 小さいクラスの標本を割合のまま使うため推定がぶれる可能性がある。既存の参照率（`build_reference_rates.py`）も
  同じ『標本不足は上位へ後退』方式で、縮約の強さを後から調整すると結果に合わせた選択になるため、式は変えていない
- 現時点で NX-1 が提供するのは、**較正された基準率（国別・3日/7日）**である。公開できる弁別力は無い

現在の影の確率は `python3 scripts/generate_nexus_candidates.py --print` で確認できる。

## Section 5・6 との関係

Section 5（周辺諸国動向）・Section 6（攻撃基盤プロファイル）は**予報の入力にしない**。
`inputs.context_inputs` は常に空で、検証器が確認する。予報側のコードが `neighbor_context` /
`infrastructure_context` を参照していないことも、テスト（`test_nexus_family.py`）が不変条件として検査する。

取り込みを検討する場合の手続きは `forecaster/config/nexus-context-preregistration.json` に**事前登録**した
（仮説・特徴量・比較方法・必要標本・採用の経路）。要点:

- 現時点で Section 5・6 の履歴は 0 日。独立標本 30 窓・履歴 60 日・陽性 20 件に届くまで評価できない
- 挑戦者でさえ基準線に勝てていないため、より複雑な特徴を足す前に、単純な特徴が効かない理由を前向きに確かめる
- 特徴量は『使う前に』候補へ記録して前向きの標本を貯める（確率には影響させない）。取り込みは別の PR と
  人間レビューで、全ゲートを満たしてから行う

## 限界

- 事象は『記録された確認』で、収集・正規化・タグ付け（LLM）の変動を含む。真の活動量ではない
- グリッド日は窓が重なる。標本数を独立標本に換算して扱う
- 歴史の起点が 2026-06-29 と短い。季節性や政治日程の影響は扱えない
- 日次ランの欠測（約 5%）は被覆の規則で除くが、欠測が事象と相関していれば偏る

## 運用

```bash
# 日次（SKILL.md Step 3.7・Step 3.6 の後）
python3 scripts/generate_nexus_candidates.py --date "${TODAY}" --cutoff-at-utc "${NEXUS_CUTOFF_UTC}" --issued-at-utc "${NEXUS_ISSUED_UTC}"
python3 scripts/validate_nexus_integrity.py --date "${TODAY}"

# 週次（.skills/forecast-verification）
python3 scripts/validate_nexus_integrity.py --all --recompute
python3 scripts/verify_nexus_forecasts.py --write [--walkforward]
```
