# Pythia Tactical Forecaster v3

Pythiaは脆弱性ニュースの要約器ではなく、観測済み事実から次に観測される戦術展開を
前向きに予報し、防御側の判断を早める「サイバー戦術予報士」である。

## 契約

1. Evidenceは取得時刻とhashを持ち、cutoffより後の情報を状態へ混ぜない。
2. ObservationはEventへ正規化し、同一CVE・同日・同状態の再報道を一つのepisode entryへ統合する。
3. 状態と予報候補は有限状態・許可遷移からコードで生成し、LLMに確率を書かせない。
4. 参照率は `current_state × target_event × next_state × horizon` ごとに測る。
5. 予報台帳は発行時にhashで凍結し、matching ruleを窓の途中で変えない。
6. bounded open worldでの未確認はmissではなく`not_observed`とする。
7. 精度だけでなくBrier、log loss、AUC、coverage、棄権率、lead timeを家族別に評価する。
8. 現在はshadow modeであり、公開予報は0件。昇格はmodel registryの人間承認を要する。

人間承認だけでも昇格できない。`promotion-gates.json` の前向き標本数、陽性数、
Brier skill、AUC下限、較正、Evidence被覆率、時間整合性をfamily×horizon別に満たした
promotion summaryが必要である。違反時はCIが拒否する。

## 現在の予報対象

TF-1は脆弱性の `DISCLOSED → POC_PUBLIC → LIMITED_EXPLOITATION →
ACTIVE_EXPLOITATION → POST_EXPLOIT_ACTIVITY` を扱う。`BROAD_CAMPAIGN`は現行データで
構造的に観測できないため、0件を低確率へ変換せず棄権する。

Actor・標的・インフラ・影響への展開予報はEvent/Case/Episodeを蓄積した後に、別family、
別matching rule、別評価母集団として追加する。TF-1の数字を流用しない。

## 日次順序

`snapshot → collect/normalize → event store → state(cutoff) → reference rates →
candidate freeze(issued) → integrity/transition validation → portfolio → report`

予報後は同じsource universeを監視し、窓満了時に決定論的に検証する。
