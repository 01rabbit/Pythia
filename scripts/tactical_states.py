#!/usr/bin/env python3
"""TF-1（悪用状態遷移）の状態機械と許可遷移を一箇所に定義する共有モジュール。

戦術予報士 v2 設計 §3 TF-1 / §4.2 に対応する。

★なぜ共有モジュールにするか:
  状態名と許可遷移が複数スクリプトに分散すると、候補生成側と採点側で解釈がずれ、
  「その日に許した遷移」と「後から採点した遷移」が食い違う。予報の採点が発行後の
  解釈に依存すると測定系が壊れるため、定義は1箇所に固定する。

★LLM は状態名を自由生成しない（設計 §8）。ここに定義された有限集合から選ぶ。
"""

# --- 状態集合（設計 §3 TF-1 の state machine）-------------------------------
DISCLOSED = "DISCLOSED"
TECHNICAL_DETAIL = "TECHNICAL_DETAIL"
POC_PUBLIC = "POC_PUBLIC"
SCANNING = "SCANNING"
LIMITED_EXPLOITATION = "LIMITED_EXPLOITATION"
ACTIVE_EXPLOITATION = "ACTIVE_EXPLOITATION"
POST_EXPLOIT_ACTIVITY = "POST_EXPLOIT_ACTIVITY"
BROAD_CAMPAIGN = "BROAD_CAMPAIGN"

STATES = [
    DISCLOSED, TECHNICAL_DETAIL, POC_PUBLIC, SCANNING,
    LIMITED_EXPLOITATION, ACTIVE_EXPLOITATION, POST_EXPLOIT_ACTIVITY, BROAD_CAMPAIGN,
]

# 進行度。上位状態へ「戻る」遷移は候補にしない（前進のみ予報する）。
STATE_RANK = {s: i for i, s in enumerate(STATES)}

# --- 観測の exploitation_stage → 状態の対応 ---------------------------------
# ★推論を挟まない機械的対応のみ。観測に無い状態（TECHNICAL_DETAIL / SCANNING）は
#   現行スキーマでは表現できないため、キーワード推定などで埋めない（原則1）。
STAGE_TO_STATE = {
    "none": DISCLOSED,
    "poc_public": POC_PUBLIC,
    "limited_exploitation": LIMITED_EXPLOITATION,
    "active_exploitation": ACTIVE_EXPLOITATION,
    # kev_listed は「CISA が実悪用を認定した」ことを意味するので悪用状態としては
    # ACTIVE_EXPLOITATION 相当だが、根拠が制度側である点を state_basis に残す。
    "kev_listed": ACTIVE_EXPLOITATION,
}
INSTITUTIONAL_STAGES = {"kev_listed"}

# 侵入後活動と判定してよい ATT&CK tactic。これらが同一CVEに紐づく観測で
# 確認されている場合のみ POST_EXPLOIT_ACTIVITY へ進める。
POST_EXPLOIT_TACTICS = {
    "persistence", "privilege-escalation", "lateral-movement",
    "credential-access", "collection", "exfiltration", "impact",
    "command-and-control", "defense-evasion",
}

# --- 許可遷移（設計 §4.2）----------------------------------------------------
# 各遷移に target event type と visibility class（設計 §9.3）を持たせる。
# visibility=low は本番確率予報にせず shadow / collection requirement へ回す。
TRANSITIONS = {
    POC_PUBLIC: [
        ("TF1_INDEPENDENT_EXPLOITATION_CONFIRMATION", LIMITED_EXPLOITATION, "medium"),
    ],
    SCANNING: [
        ("TF1_INDEPENDENT_EXPLOITATION_CONFIRMATION", LIMITED_EXPLOITATION, "medium"),
    ],
    LIMITED_EXPLOITATION: [
        ("TF1_BROADER_EXPLOITATION_CONFIRMATION", ACTIVE_EXPLOITATION, "medium"),
    ],
    ACTIVE_EXPLOITATION: [
        ("TF1_POST_EXPLOIT_ACTIVITY_PUBLICATION", POST_EXPLOIT_ACTIVITY, "medium"),
        ("TF1_BROAD_CAMPAIGN", BROAD_CAMPAIGN, "low"),
    ],
    DISCLOSED: [
        ("TF1_POC_PUBLICATION", POC_PUBLIC, "medium"),
    ],
    TECHNICAL_DETAIL: [
        ("TF1_POC_PUBLICATION", POC_PUBLIC, "medium"),
    ],
}

# IF-1（制度予報・設計 §3 IF-1）。TF と混ぜて集計しない。
IF1_EVENT = "IF1_CISA_KEV_INITIAL_ADD"
IF1_VISIBILITY = "high"  # 固定一次ソース（KEVカタログ本体）で網羅確認できる

# 予報する時間軸（設計 §5.4）。確率は P72h <= P7d <= P30d を満たすこと。
HORIZONS_DAYS = [3, 7, 30]
HORIZON_LABELS = {3: "72h", 7: "7d", 30: "30d"}

VISIBILITY_CLASSES = {"high", "medium", "low"}
STATE_CONFIDENCE = {"confirmed", "probable", "uncertain"}


def allowed_transitions(state):
    """その状態から予報してよい (event_type, next_state, visibility) を返す。"""
    return list(TRANSITIONS.get(state, []))


def is_forward(from_state, to_state):
    """前進遷移か（後退・自己ループは予報候補にしない）。"""
    return STATE_RANK.get(to_state, -1) > STATE_RANK.get(from_state, -1)


def state_from_stage(stage):
    """観測の exploitation_stage から状態を引く。未対応なら None。"""
    return STAGE_TO_STATE.get(stage)


def reference_key(from_state, event_type, next_state, horizon_days):
    """target-event別参照クラスの安定キーを返す。"""
    return "|".join((
        "TF1", from_state, event_type, next_state, HORIZON_LABELS[horizon_days]
    ))


def transition_fired(event_type, observed_state, next_state):
    """観測状態が特定target eventの成立を証明するか。

    PoC公開は後続の悪用確認から論理的に導けないためexact matchとする。
    悪用の広がり・侵入後活動は上位状態が下位状態の成立を含意する。
    """
    if event_type == "TF1_POC_PUBLICATION":
        return observed_state == POC_PUBLIC
    if event_type == "TF1_BROAD_CAMPAIGN":
        return observed_state == BROAD_CAMPAIGN
    return STATE_RANK.get(observed_state, -1) >= STATE_RANK.get(next_state, 999)


def derive_state(observation, subject_id=None):
    """1観測から TF-1 の状態を導く。(state, basis) を返す。導けなければ (None, None)。

    ★機械的な対応のみで、本文からのキーワード推定は行わない（原則1）。
    根拠は2つだけ:
      1. exploitation_stage の機械的対応（STAGE_TO_STATE）
      2. 侵入後 tactic の Technique が付いていれば POST_EXPLOIT_ACTIVITY
         — Technique は 01-normalize.md R3 により「情報源が具体的手口を記述して
           いる場合のみ」付与されているので、これは推測ではなく記録された事実である

    両方が導ける場合は前進度の高い方を採る（後退はしない）。
    """
    stage = observation.get("exploitation_stage")
    base = STAGE_TO_STATE.get(stage)
    basis = ("institutional_kev" if stage in INSTITUTIONAL_STAGES
             else "exploitation_stage") if base else None

    cves = observation.get("cve") or []
    tactics = set()
    for t in (observation.get("techniques") or []):
        if not isinstance(t, dict):
            continue
        scope = t.get("scope_ref")
        if scope:
            if subject_id and scope != subject_id:
                continue
        elif subject_id and not (len(cves) == 1 and cves[0] == subject_id):
            # 複数CVE記事のcampaign-level Techniqueを全CVEへ伝播しない。
            continue
        tactics.add(t.get("tactic"))
    if tactics & POST_EXPLOIT_TACTICS:
        # 侵入後 tactic が確認されている ＝ 悪用が成立して次段階に進んでいる
        if base is None or STATE_RANK[POST_EXPLOIT_ACTIVITY] > STATE_RANK[base]:
            return POST_EXPLOIT_ACTIVITY, "post_exploit_technique"
    return base, basis
