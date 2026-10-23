#!/usr/bin/env python
"""| cgarango - upsert search results into ArangoDB (documents or edges).

Documents:
    ... | cgarango collection=changes key=chg_number fields="summary,status,approval"
    ... | cgarango collection_field=target_col key=ci_id
Edges (from/to hold 'collection/key'; the edge key defaults to a hash of the endpoints):
    ... | eval from="changes/".chg_number, to="cis/".ci_id | cgarango collection=chg_affects from=from to=to

Writes are batched per search chunk and are upserts (merge), so re-running is safe.
Rows pass through with arango_status=ok|error:...
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch, validators  # noqa: E402

from changeguard_core.commands import write_chunk  # noqa: E402
from changeguard_core.config import client_from_splunk  # noqa: E402


@Configuration()
class CgArangoCommand(EventingCommand):
    collection = Option(require=False, doc="Target collection")
    collection_field = Option(require=False, doc="Field naming the target collection per row")
    key = Option(require=False, doc="Field holding the document _key (documents: required unless _key exists)")
    from_ = Option(name="from", require=False, doc="Edge source id field ('collection/key')")
    to = Option(require=False, doc="Edge target id field ('collection/key')")
    fields = Option(require=False, doc="Comma-separated fields to store (default: all non-underscore fields)")
    multivalue = Option(require=False, doc="Comma-separated fields always stored as lists")
    on_error = Option(require=False, default="fail", validate=validators.Set("fail", "mark"))

    def transform(self, records):
        if not (self.collection or self.collection_field):
            raise ValueError("cgarango needs collection= or collection_field=")
        if bool(self.from_) != bool(self.to):
            raise ValueError("cgarango edges need both from= and to=")
        client = client_from_splunk(self.service)
        for record in write_chunk(
            client, records, collection=self.collection, collection_field=self.collection_field,
            key_field=self.key, from_field=self.from_, to_field=self.to, fields=self.fields,
            multivalue=self.multivalue, on_error=self.on_error,
        ):
            yield record


dispatch(CgArangoCommand, sys.argv, sys.stdin, sys.stdout, __name__)
