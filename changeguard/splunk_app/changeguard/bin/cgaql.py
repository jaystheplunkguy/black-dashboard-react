#!/usr/bin/env python
"""| cgaql - run a named ChangeGuard AQL query for every row and merge the result in.

    | inputlookup cg_cases_lookup where status="watch" | cgaql query=downstream_incidents prefix=w_ params="devices=doi"
    | cgaql query=alt_explanations prefix=alt_ params="devices=doi"
    | cgaql query=case_evidence mode=json out=evidence_json

Bind parameters are read from fields with the same name (override with params="param=field,...").
Only queries registered in changeguard_core/queries.py can run. On failure the row gets aql_error
(on_error=mark, default) so the pipeline can skip it and retry next run.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, Option, StreamingCommand, dispatch, validators  # noqa: E402

from changeguard_core.commands import enrich  # noqa: E402
from changeguard_core.config import client_from_splunk  # noqa: E402


@Configuration(distributed=False)
class CgAqlCommand(StreamingCommand):
    query = Option(require=True, doc="Name of a registered query")
    prefix = Option(require=False, default="", doc="Prefix for output fields")
    mode = Option(require=False, default="first", validate=validators.Set("first", "all", "json"))
    out = Option(require=False, default="aql_json", doc="Output field for mode=json")
    params = Option(require=False, doc="Bind param to field mapping: param=field,...")
    on_error = Option(require=False, default="mark", validate=validators.Set("fail", "mark"))

    def stream(self, records):
        client = client_from_splunk(self.service)
        for record in enrich(client, records, self.query, prefix=self.prefix, mode=self.mode,
                             out_field=self.out, param_map=self.params, on_error=self.on_error):
            yield record


dispatch(CgAqlCommand, sys.argv, sys.stdin, sys.stdout, __name__)
