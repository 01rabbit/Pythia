#!/usr/bin/env python3
"""発行済み予報サイドカーJSONの内部整合を機械的に検査する（読み取り専用）。

背景:
  検証ステージ（04-verify.md）が確定した外れの中に、予報ロジックの誤りではなく
  **発行時の記述ミス**に起因するものが混ざっていた。過去に実測された2類型:

    Issue #162  hit_criteria の dateAdded 範囲の起点が予報ごとに揺れていた。
                2026-08-21 発行の Zimbra CVE-2026-73570 は範囲を「08-22〜08-24」
                （forecast_date+1 起点）と書いたため、実際の初回追加
                dateAdded=2026-08-21 を構造的に窓外に置き「外れ」となった。
                同じ Issue で、前日の予報文言をひな型に使って日付範囲を更新し忘れた
                例（2026-08-20 発行の TrueConf 予報が前日 MLflow 予報の
                「08-19〜08-22」をそのまま記載）も確認されている。

    Issue #132  outcome_channel=E3 の hit_criteria が、E3 の固定一次ソース
                （JPCERT/CC・IPA・CERT/CC）ではなく米国機関（CISA/FBI/NSA/WaterISAC）の
                発行を的中条件にしていた。出口クラスの割当と参照ソースが食い違うと
                M1-b 頻度ゲートが別チャネルの実測ハザードで判定してしまう。
                同 Issue では related_observation_ids が無関係な観測を指していた例
                （fc-20260805-1 が Apache Tomcat の観測を参照）も確認されている。

  いずれも人手のレビューでは見落とされ、検証まで気づけなかった。本スクリプトは
  発行前（SKILL.md Step 3.5 の直後）にこの種の記述ミスを機械的に落とす。

検査項目（[E]=エラー・終了コード1 / [W]=警告のみ）:
  [E] deadline_date が forecast_class から決まる期限と一致する（fast_72h は +3日）
  [E] hit_criteria に書かれた日付範囲の両端が [forecast_date, deadline_date] と一致する
      （起点の揺れと、前日文言の使い回しによる更新漏れの双方を検出する）
  [E] outcome_channel=E1 の hit_criteria に dateAdded の判定範囲が明示されている
  [E] outcome_channel=E3 の hit_criteria が E3 の固定一次ソース（JPCERT/CC・IPA・CERT/CC）の
      いずれかを発行主体として名指ししている
  [E] related_observation_ids が実在する観測 ID を指している
  [E] 新証拠なしに同一CVEを再予報していない（改善計画 §5.1・--all 時のみ）
  [W] E1 の範囲が「YYYY-MM-DD 以降」のように終点を明示していない
  [W] E3 の hit_criteria に米国機関名が併記されている（文脈言及か的中条件かの確認を促す）
  [W] related_observation_ids の参照先観測が予報の主題（CVE番号）と一致しない
      （CVEを含まない主題の予報では判定できないため警告に留める）

★日付の検査は「範囲表現」（`YYYY-MM-DD〜YYYY-MM-DD` 等）と「起点のみの表現」
  （`YYYY-MM-DD 以降` 等）に限定して行う。hit_criteria 本文には引き金となった勧告の
  発行日など窓とは無関係な日付も現れるため、本文中のすべての日付を窓に照合すると
  偽陽性になる（実例: fc-20260801-1 の「CISA緊急勧告2026-07-30」）。

★このスクリプトは読み取り専用であり、forecaster/knowledge/ を含む一切のファイルを
  書き換えない（CLAUDE.md 行動原則5）。判定基準（hit_criteria）そのものの事後変更にも
  使わない（原則D・教訓12）。過去分の違反を検出しても、発行済み予報は修正しない。

使い方:
    # 当日分を検査（既定は JST の本日）
    python3 scripts/check_forecast_consistency.py

    # 日付を指定
    python3 scripts/check_forecast_consistency.py --date 2026-08-21

    # 全履歴を一括検査（回帰確認用・既知の未修正分は下記のとおり）
    python3 scripts/check_forecast_consistency.py --all

既知の未修正分（本スクリプト導入時点＝2026-08-29 の実測ベースライン・`--all` で再現する）:
  検査55ファイル / エラー12件 / 警告7件

  [E] hit_criteria に dateAdded の範囲が明示されていない
      2026-07-07 fc-20260707-1 / 2026-07-11 fc-20260711-1 / 2026-07-13 fc-20260713-1 /
      2026-07-26 fc-20260726-1（「72時間以内」「検証窓内」等の相対表現のみ）
  [E] 範囲の起点が forecast_date+1（発行当日の初回追加を窓外へ置く・Issue #162）
      2026-08-08 fc-20260808-1 / 2026-08-21 fc-20260821-1,-2 / 2026-08-26 fc-20260826-1
  [E] 前日文言の使い回しによる起点の更新漏れ（Issue #162）
      2026-08-20 fc-20260820-1（前日 MLflow 予報の 2026-08-19 起点をそのまま記載）
  [E] deadline_date が forecast_date+3 でない
      2026-07-29 fc-20260729-1（+2）/ 2026-08-20 fc-20260820-1（+2）
  [E] E3 の的中条件が固定一次ソースを名指ししていない（Issue #132 所見1）
      2026-08-06 fc-20260806-1（CISA/FBI/NSA/WaterISAC を条件にしている）

  ★発行済み予報は当時の記録であり、`hit_criteria` も判定結果も修正しない（原則D・教訓12）。
  したがって `--all` が非ゼロで終了するのは想定内である。日次の発行前チェックでは
  `--date` を使い当日分のみを対象にすること（2026-08-27 以降の発行分は 0 件で通過する）。
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORECAST_DIR = os.path.join(REPO_ROOT, "forecaster", "forecasts", "daily")
OBSERVATION_DIR = os.path.join(REPO_ROOT, "forecaster", "observations")

JST = timezone(timedelta(hours=9))

# fast_72h は「発行日+3」固定（03-forecast.md「検証期限」）。
# slow_7d は主題別の分類表に従うため日数を一意に決められず、本スクリプトでは検査しない。
FAST_WINDOW_DAYS = 3

# E3 の固定一次ソース（pipeline-forecast-verification.md「観測出口クラス」表）。
E3_ALLOWED_SOURCES = ("JPCERT", "IPA", "CERT/CC", "情報処理推進機構")

# E3 の的中条件に現れてはならない機関（Issue #132 所見1 の実例に基づく）。
E3_FOREIGN_AGENCIES = ("CISA", "FBI", "NSA", "WaterISAC", "NCSC", "ACSC")

DATE = r"(20\d{2})[-/年](\d{1,2})[-/月](\d{1,2})日?"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# 「2026-08-21〜2026-08-24」「2026-08-21 から 2026-08-24」等の範囲表現。
RANGE_RE = re.compile(DATE + r"\s*(?:〜|~|-{1,2}|から|–|—)\s*" + DATE)
# 「2026-08-21 以降」「2026-08-21 以後」等の起点のみの表現。
OPEN_START_RE = re.compile(DATE + r"\s*(?:以降|以後|から)")


def _to_date(y, m, d):
    try:
        return date(int(y), int(m), int(d))
    except ValueError:
        return None


def parse_window(text):
    """hit_criteria から窓を表す (start, end) を取り出す。

    戻り値は (start, end) で、範囲表現があれば両端、起点のみの表現なら (start, None)、
    どちらも無ければ (None, None)。窓とは無関係な日付（勧告の発行日など）を拾わないよう、
    範囲表現・起点表現に現れる日付だけを対象にする。
    """
    text = text or ""
    m = RANGE_RE.search(text)
    if m:
        return _to_date(*m.group(1, 2, 3)), _to_date(*m.group(4, 5, 6))
    m = OPEN_START_RE.search(text)
    if m:
        return _to_date(*m.group(1, 2, 3)), None
    return None, None


def load_observation_index(forecast_date):
    """予報日の前後3日分の観測 ID → observation を索く辞書を返す。

    予報は当日の観測を参照するのが基本だが、前日以前の観測を根拠にすることもあるため
    前後に余裕を持たせる（誤参照検出が目的であり、範囲外参照そのものは咎めない）。
    """
    index = {}
    for delta in range(-3, 4):
        d = forecast_date + timedelta(days=delta)
        path = os.path.join(
            OBSERVATION_DIR, f"{d.year:04d}", f"{d.month:02d}", f"{d.isoformat()}.json"
        )
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for obs in data.get("observations", []):
            oid = obs.get("observation_id")
            if oid:
                index[oid] = obs
    return index


def check_deadline(fc, forecast_date, errors):
    deadline = fc.get("deadline_date")
    if not deadline:
        errors.append("deadline_date が未記入")
        return None
    try:
        deadline_d = datetime.strptime(deadline, "%Y-%m-%d").date()
    except ValueError:
        errors.append(f"deadline_date の書式が不正: {deadline!r}")
        return None
    if fc.get("forecast_class") == "fast_72h":
        expected = forecast_date + timedelta(days=FAST_WINDOW_DAYS)
        if deadline_d != expected:
            errors.append(
                f"fast_72h の deadline_date は forecast_date+{FAST_WINDOW_DAYS} "
                f"（{expected}）でなければならないが {deadline_d} である"
            )
    return deadline_d


def check_hit_criteria_dates(fc, forecast_date, deadline_d, errors, warnings):
    """hit_criteria の窓表現が [forecast_date, deadline_date] と一致するか検査する。

    03-forecast.md「M4-b hit_criteria の日付範囲の記述規則」に対応する。
    """
    if deadline_d is None:
        return
    start, end = parse_window(fc.get("hit_criteria"))
    is_e1 = fc.get("outcome_channel") == "E1"

    if start is None:
        if is_e1:
            errors.append(
                "E1 予報の hit_criteria に dateAdded の判定範囲が明示されていない"
                f"（M4-b: 「{forecast_date}〜{deadline_d}（両端を含む）」の形で書く）"
            )
        return

    if start != forecast_date:
        errors.append(
            f"hit_criteria の範囲の起点は forecast_date（{forecast_date}）でなければ"
            f"ならないが {start} である"
            + (
                "（発行当日の KEV 初回追加を構造的に窓外へ置く・Issue #162）"
                if start > forecast_date
                else "（前日の予報文言を使い回した際の更新漏れの可能性・Issue #162）"
            )
        )
    if end is None:
        warnings.append(
            f"hit_criteria の範囲が「{start} 以降」の形で終点を明示していない"
            f"（M4-b: 終点 {deadline_d} を明記する）"
        )
    elif end != deadline_d:
        errors.append(
            f"hit_criteria の範囲の終点は deadline_date（{deadline_d}）でなければ"
            f"ならないが {end} である"
        )


def check_e3_sources(fc, errors, warnings):
    """E3 の hit_criteria が固定一次ソースを発行主体にしているか検査する。

    米国機関名が現れること自体は誤りではない（引き金となった事案の言及として
    正当に現れる。例: fc-20260801-1 の「CISA緊急勧告2026-07-30」）。誤りなのは
    固定一次ソースが1つも名指しされていない場合であり、そのとき的中条件は
    E3 以外のチャネルを指している（Issue #132 所見1）。
    """
    if fc.get("outcome_channel") != "E3":
        return
    hit = (fc.get("hit_criteria") or "").lower()
    allowed = [a for a in E3_ALLOWED_SOURCES if a.lower() in hit]
    foreign = [a for a in E3_FOREIGN_AGENCIES if a.lower() in hit]
    if not allowed:
        errors.append(
            "E3 の hit_criteria が固定一次ソース（"
            + "・".join(E3_ALLOWED_SOURCES[:3])
            + "）を発行主体として名指ししていない"
            + (f"（代わりに {', '.join(foreign)} を条件にしている）" if foreign else "")
            + "。E3 の実測ハザード 0.015 は JPCERT/CC・IPA を母集団とする値であり"
            "他機関の発行頻度を測っていない（Issue #132）"
        )
    elif foreign:
        warnings.append(
            "E3 の hit_criteria に米国機関名が併記されている: "
            + ", ".join(foreign)
            + "。文脈の言及であれば問題ないが、的中条件の発行主体に含めてはならない"
        )


def check_related_observations(fc, obs_index, errors, warnings):
    ids = fc.get("related_observation_ids") or []
    subject_cves = {
        c.upper()
        for c in CVE_RE.findall(
            " ".join(
                str(fc.get(k) or "")
                for k in ("subject", "hit_criteria", "evidence")
            )
        )
    }
    kev_cve = (fc.get("kev_snapshot") or {}).get("cve")
    if kev_cve:
        subject_cves.add(kev_cve.upper())

    for oid in ids:
        obs = obs_index.get(oid)
        if obs is None:
            errors.append(
                f"related_observation_ids の参照先が実在しない: {oid}"
                "（予報日の前後3日分の観測ファイルを走査した）"
            )
            continue
        if not subject_cves:
            continue
        obs_cves = {c.upper() for c in (obs.get("cve") or [])}
        obs_cves |= {c.upper() for c in CVE_RE.findall(obs.get("summary") or "")}
        if obs_cves and not (obs_cves & subject_cves):
            warnings.append(
                f"related_observation_ids={oid} の観測は予報の主題 CVE"
                f"（{', '.join(sorted(subject_cves))}）と一致しない"
                f"（参照先の CVE: {', '.join(sorted(obs_cves))}）"
                "。無関係な観測を指していないか確認する（Issue #132 所見2）"
            )


def check_file(path):
    """1日分の予報ファイルを検査し (errors, warnings) を返す。"""
    errors, warnings = [], []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        return [f"{os.path.basename(path)}: 読み取り失敗: {exc}"], []
    except json.JSONDecodeError as exc:
        return [f"{os.path.basename(path)}: JSON 構文エラー: {exc}"], []

    fd_str = data.get("_forecast_date") or os.path.basename(path)[:10]
    try:
        forecast_date = datetime.strptime(fd_str, "%Y-%m-%d").date()
    except ValueError:
        return [f"{os.path.basename(path)}: _forecast_date が不正: {fd_str!r}"], []

    forecasts = data.get("forecasts") or []
    if not forecasts:
        return errors, warnings

    obs_index = load_observation_index(forecast_date)

    for fc in forecasts:
        fid = fc.get("forecast_id") or f"index={fc.get('forecast_index')}"
        local_e, local_w = [], []
        deadline_d = check_deadline(fc, forecast_date, local_e)
        check_hit_criteria_dates(fc, forecast_date, deadline_d, local_e, local_w)
        check_e3_sources(fc, local_e, local_w)
        check_related_observations(fc, obs_index, local_e, local_w)
        errors.extend(f"{fid}: {m}" for m in local_e)
        warnings.extend(f"{fid}: {m}" for m in local_w)
    return errors, warnings


def check_reforecast(paths, effective_from="2026-08-30"):
    """新証拠なしの同一CVE再予報を検出する（改善計画 §5.1・§11 の fail-closed 条件）。

    同じCVEを翌日以降にもう一度予報すると、当たるまで試行を繰り返すのと同じになり、
    予報件数が独立試行でなくなる。実測では E1 24件のうち3組が同一CVEの再予報で、
    いずれも両方とも外れだった（CVE-2026-20896 / -59310 / -71362）。

    「新証拠」の判定は evidence_ids の差分で行う。前回の予報が参照していない
    evidence_id が1件以上含まれていれば新証拠ありとみなす。evidence_ids を持たない
    v1.0 の予報は判定材料がないため対象外（遡及して violation にしない・原則D）。
    """
    errors = []
    seen = {}  # cve -> (forecast_date, forecast_id, frozenset(evidence_ids))
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("_schema_version") != "2.0":
            continue
        fdate = data.get("_forecast_date") or os.path.basename(path)[:10]
        if fdate < effective_from:
            continue
        for fc in data.get("forecasts", []):
            te = fc.get("target_event") or {}
            entity = te.get("entity_id")
            if not entity:
                continue
            ev = frozenset(fc.get("evidence_ids") or [])
            prev = seen.get(entity)
            if prev and not (ev - prev[2]):
                errors.append(
                    f"{os.path.basename(path)}: {fc.get('forecast_id')}: "
                    f"{entity} は {prev[0]}（{prev[1]}）で予報済みで、新しい証拠がない。"
                    "新情報は既存予報の証拠更新として扱い、期限を延長せずに再予報しない"
                    "（改善計画 §5.1）"
                )
            if not prev or (ev - prev[2]):
                seen[entity] = (fdate, fc.get("forecast_id"), ev | (prev[2] if prev else frozenset()))
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", help="検査対象日 YYYY-MM-DD（既定: JST の本日）")
    ap.add_argument("--all", action="store_true", help="全履歴を一括検査する")
    args = ap.parse_args()

    if args.all:
        paths = sorted(glob.glob(os.path.join(FORECAST_DIR, "*.json")))
    else:
        target = args.date or datetime.now(JST).date().isoformat()
        paths = [os.path.join(FORECAST_DIR, f"{target}.json")]
        if not os.path.exists(paths[0]):
            print(f"[E] 予報ファイルが存在しない: {paths[0]}", file=sys.stderr)
            return 1

    total_e = total_w = 0
    for path in paths:
        errors, warnings = check_file(path)
        if not errors and not warnings:
            continue
        print(f"\n=== {os.path.basename(path)} ===")
        for m in errors:
            print(f"  [E] {m}")
        for m in warnings:
            print(f"  [W] {m}")
        total_e += len(errors)
        total_w += len(warnings)

    # 再予報の検査は日をまたいだ比較が要るため、常に全履歴を走査する
    # （--date 指定でも、その日の予報が過去の再予報でないかを見る必要がある）。
    all_paths = sorted(glob.glob(os.path.join(FORECAST_DIR, "*.json")))
    reforecast = check_reforecast(all_paths)
    if reforecast:
        print("\n=== 再予報の検査（新証拠なしの同一CVE再予報）===")
        for m in reforecast:
            print(f"  [E] {m}")
        total_e += len(reforecast)

    print(f"\n検査ファイル数 {len(paths)} / エラー {total_e} 件 / 警告 {total_w} 件")
    return 1 if total_e else 0


if __name__ == "__main__":
    sys.exit(main())
