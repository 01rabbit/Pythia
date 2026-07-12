#!/usr/bin/env python3
"""日次ルーチンのコミット前チェック: forecaster/knowledge/ が無変更であることを機械的に確認する。

CLAUDE.md 行動原則5「knowledge/ の自動書き換え禁止」の機械的ガード。
日次ルーチン（SKILL.md Step 4）のコミット直前チェックに組み込み、
knowledge/ 配下に未コミットの変更・新規ファイルがあれば exit 1 で失敗させる。
（knowledge/ の変更は必ず PR 提案+人間レビュー経由で行う。日次実行で本チェックが
失敗した場合、変更を revert してから日次コミットを行い、意図した補正であれば
別途 Issue/PR として提案すること。）

使い方:
    python3 scripts/check_knowledge_untouched.py
"""

import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWLEDGE_DIR = "forecaster/knowledge"


def main():
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", KNOWLEDGE_DIR],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    dirty = [line for line in result.stdout.splitlines() if line.strip()]
    if dirty:
        print(
            f"NG: {KNOWLEDGE_DIR}/ に未コミットの変更があります"
            "（行動原則5: knowledge/ の自動書き換え禁止）:"
        )
        for line in dirty:
            print(f"  {line}")
        print(
            "対応: 変更を revert してから日次コミットを行うこと。"
            "意図した補正は Issue/PR として提案し人間レビューを経ること。"
        )
        return 1
    print(f"OK: {KNOWLEDGE_DIR}/ に未コミットの変更なし。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
