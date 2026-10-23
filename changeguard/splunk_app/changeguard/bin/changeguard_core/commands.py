"""Logic behind the cgarango / cgaql search commands, kept free of splunklib so it is testable."""

import json

from .arango import ArangoError
from .docs import build_documents, flatten, uniform
from .queries import QUERIES, bind


def write_chunk(client, records, collection=None, collection_field=None, key_field=None,
                from_field=None, to_field=None, fields=None, multivalue=None, on_error="fail"):
    """Upsert one chunk of Splunk rows into ArangoDB; return the rows annotated with arango_status."""
    records = list(records)
    grouped, skipped = build_documents(
        records, collection=collection, collection_field=collection_field, key_field=key_field,
        from_field=from_field, to_field=to_field, fields=fields, multivalue=multivalue,
    )
    status = "ok"
    try:
        for target, docs in grouped.items():
            client.upsert(target, docs)
    except ArangoError as exc:
        if on_error != "mark":
            raise
        status = "error: %s" % exc
    for record in records:
        record["arango_status"] = status
        record["arango_skipped"] = skipped
    return records


def _param_values(record, query, param_map):
    """Bind values come from same-named fields, or from fields renamed via params="param=field,..."."""
    mapping = {}
    for pair in (param_map or "").split(","):
        if "=" in pair:
            param, field = pair.split("=", 1)
            mapping[param.strip()] = field.strip()
    return {name: record.get(mapping.get(name, name)) for name in query.params}


def enrich(client, records, query_name, **options):
    """Buffered, column-uniform version of iter_enrich (what the search command uses)."""
    return uniform(iter_enrich(client, records, query_name, **options))


def iter_enrich(client, records, query_name, prefix="", mode="first", out_field="aql_json",
                param_map=None, on_error="mark"):
    """Run a named query once per row and merge the result into it.

    mode=first: flatten the first result into prefixed fields
    mode=all:   one output row per result (input row kept, with <prefix>count=0, when empty)
    mode=json:  the whole result list as JSON in out_field
    """
    query = QUERIES.get(query_name)
    if query is None:
        raise ValueError("unknown query '%s'; known: %s" % (query_name, ", ".join(sorted(QUERIES))))
    for record in records:
        try:
            results = client.aql(query.aql, bind(query, _param_values(record, query, param_map)))
        except (ArangoError, ValueError) as exc:
            if on_error != "mark":
                raise
            record["aql_error"] = str(exc)
            yield record
            continue
        if mode == "json":
            record[out_field] = json.dumps(results, sort_keys=True)
            yield record
        elif mode == "all":
            if not results:
                record[prefix + "count"] = 0
                yield record
            for result in results:
                row = dict(record)
                row.update(flatten(result, prefix))
                row[prefix + "count"] = len(results)
                yield row
        else:
            if results:
                record.update(flatten(results[0], prefix))
            record[prefix + "count"] = len(results)
            yield record
