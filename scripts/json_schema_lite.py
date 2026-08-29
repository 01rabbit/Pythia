#!/usr/bin/env python3
"""forecaster/schema/*.json を実際に強制するための最小 JSON Schema 検証器。

★なぜ自前で書くか:
  この repo は日次パイプラインも CI も**標準ライブラリだけ**で動く（CI に依存
  インストール手順が無い）。jsonschema を持ち込むと、検証が依存解決に依存する。
  検証系は依存が最も少ない層であるべきなので、使っている語彙だけを実装する。

★なぜ必要か:
  スキーマを置いても、それを読むコードが無ければ**契約ではなく文書**にすぎない。
  実際 `tactical-state.schema.json` は誰からも参照されておらず、
  `post_exploit_evidence` の追加はスキーマを素通りした。宣言と成果物が黙って
  乖離するのを止めるのがこのモジュールの役割である。

対応語彙（スキーマ群で実際に使われているものだけ）:
  type / required / properties / additionalProperties / items / enum / const /
  pattern / minimum / maximum / minItems / maxItems / anyOf / $ref（$defs 内のみ）

対応しない語彙:
  format は**検証しない**（date-time 等を自前正規表現で判定すると、正しい値を
  誤って落とす危険のほうが大きい）。必要な形式検査は各スキーマの pattern か、
  呼び出し側の個別検証で行う。
"""

import re

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}


def _type_ok(value, expected):
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    py = _TYPES.get(expected)
    return isinstance(value, py) if py else True


def _resolve(ref, root):
    """`#/$defs/name` 形式だけを解決する。それ以外は未対応として素通しする。"""
    if not ref.startswith("#/"):
        return None
    node = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def validate(instance, schema, root=None, path="$"):
    """(instance, schema) を検証し、違反メッセージのリストを返す。"""
    root = schema if root is None else root
    errors = []
    if not isinstance(schema, dict):
        return errors

    if "$ref" in schema:
        target = _resolve(schema["$ref"], root)
        if target is not None:
            return validate(instance, target, root, path)

    if "anyOf" in schema:
        if not any(not validate(instance, sub, root, path) for sub in schema["anyOf"]):
            errors.append(f"{path}: anyOf のいずれにも一致しない")
        return errors

    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(instance, t) for t in allowed):
            errors.append(f"{path}: type 違反（期待 {allowed} / 実際 {type(instance).__name__}）")
            return errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: const 違反（期待 {schema['const']!r} / 実際 {instance!r}）")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: enum 違反（{instance!r} は許可値にない）")
    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            errors.append(f"{path}: pattern 違反（{schema['pattern']} に一致しない: {instance!r}）")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: minimum 違反（{instance} < {schema['minimum']}）")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: maximum 違反（{instance} > {schema['maximum']}）")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}.{key}: 必須フィールドが欠落")
        props = schema.get("properties") or {}
        for key, value in instance.items():
            if key in props:
                errors.extend(validate(value, props[key], root, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: スキーマに定義されていないフィールド")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: minItems 違反（{len(instance)} < {schema['minItems']}）")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: maxItems 違反（{len(instance)} > {schema['maxItems']}）")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(instance):
                errors.extend(validate(item, item_schema, root, f"{path}[{i}]"))

    return errors
