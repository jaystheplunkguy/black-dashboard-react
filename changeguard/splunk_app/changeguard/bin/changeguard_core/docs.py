"""Turn Splunk result rows into ArangoDB documents/edges, and AQL results back into rows."""

import json
import re

from .keys import edge_key, safe_id, safe_key

_NUMBER = re.compile(r"^-?(0|[1-9]\d{0,14})(\.\d+)?$")


def coerce(value):
    """Splunk hands every value over as a string; restore numbers and booleans.

    Strings with leading zeros (e.g. CI ids like '000123') stay strings.
    """
    if isinstance(value, list):
        values = [coerce(v) for v in value if v not in (None, "")]
        return values or None
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        return value
    if _NUMBER.match(value):
        return float(value) if "." in value else int(value)
    if value in ("true", "false"):
        return value == "true"
    return value


def _split_csv(text):
    return [part.strip() for part in (text or "").split(",") if part.strip()]


def build_documents(records, collection=None, collection_field=None, key_field=None,
                    from_field=None, to_field=None, fields=None, edge_label_field=None, multivalue=None):
    """Group rows by target collection and convert them into documents.

    - collection / collection_field: fixed collection, or the field naming it per row.
    - key_field: field holding the document key (sanitised). Edges default to a
      hash of their endpoints so reloading never duplicates them.
    - from_field / to_field: fields holding 'collection/key' ids (edges only).
    - fields: comma-separated whitelist; default is every non-underscore field.
    - multivalue: comma-separated fields always stored as lists (Splunk sends a
      one-value multivalue field as a plain string).

    Returns ({collection: [docs]}, skipped_count).
    """
    wanted = _split_csv(fields) if fields else None
    as_list = set(_split_csv(multivalue))
    reserved = {f for f in (collection_field, key_field, from_field, to_field) if f}
    grouped = {}
    skipped = 0
    for record in records:
        target = record.get(collection_field) if collection_field else collection
        if not target:
            skipped += 1
            continue
        doc = {}
        names = wanted if wanted is not None else [n for n in record if not n.startswith("_")]
        for name in names:
            if name in reserved and name not in (wanted or []):
                continue
            value = coerce(record.get(name))
            if value is not None:
                doc[name] = [value] if name in as_list and not isinstance(value, list) else value
        try:
            if from_field or to_field:
                doc["_from"] = safe_id(None, record[from_field])
                doc["_to"] = safe_id(None, record[to_field])
                label = record.get(edge_label_field) if edge_label_field else None
                raw_key = record.get(key_field) if key_field else None
                doc["_key"] = safe_key(raw_key) if raw_key else edge_key(doc["_from"], doc["_to"], label)
            else:
                doc["_key"] = safe_key(record.get(key_field or "_key"))
        except (KeyError, ValueError, TypeError):
            skipped += 1
            continue
        grouped.setdefault(target, []).append(doc)
    return grouped, skipped


def flatten(obj, prefix=""):
    """Flatten an AQL result object into Splunk fields.

    Scalars stay scalars, lists of scalars become multivalue fields, nested
    objects are flattened with '_' and lists of objects become JSON strings.
    """
    out = {}
    if not isinstance(obj, dict):
        out[prefix + "value"] = _scalar(obj)
        return out
    for name, value in obj.items():
        if name in ("_id", "_rev"):
            continue
        field = prefix + name.lstrip("_") if name.startswith("_") else prefix + name
        if isinstance(value, dict):
            out.update(flatten(value, field + "_"))
        elif isinstance(value, list):
            if all(not isinstance(v, (dict, list)) for v in value):
                out[field] = [_scalar(v) for v in value]
            else:
                out[field] = json.dumps(value, sort_keys=True)
        else:
            out[field] = _scalar(value)
    return out


def uniform(records):
    """Give every row the same keys (missing -> None).

    splunklib fixes a chunk's columns from its first row, so fields that only
    appear in later rows would otherwise be silently dropped.
    """
    records = list(records)
    names = []
    seen = set()
    for record in records:
        for name in record:
            if name not in seen:
                seen.add(name)
                names.append(name)
    for record in records:
        for name in names:
            record.setdefault(name, None)
    return records


def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return value
