# Controlled context investigation example

`context-tools/` is an inert, author-created two-file development fixture for
reviewing cross-file context. It is not an independently labeled benchmark,
production application, MCP server implementation, or a proof of real-model
detection accuracy. Do not import or execute its code. Its reserved `.invalid`
destination is an example, and the user-selected destination is intentionally
unrestricted by this fixture; the scanner reads these files without executing
them. No real credentials are present.

The agent-like entry point `tool_forward` passes a caller-selected address and
record to an imported dispatcher in lane `1`. The dispatcher calls `requests.post`
after a predicate which accepts every address in lane `1`. A separate lane `0`
caller uses a constant address. `allow_redirects=False` is relevant counterevidence
for redirect handling, but does not restrict the original caller-selected address.
The review must join the entry point, dispatcher, predicate and lane selection
before proposing a conclusion; a check's name or the existence of a predicate is
insufficient evidence of enforcement.

The predicate is intentionally outside the highest-ranking deterministic seed
excerpts for the `EXEC-05` control. The bounded investigator can select its
file ID and lines from the captured manifest's definition hints. It cannot open
arbitrary paths, run these functions, call the example destination, or declare
deployed exploitability. The existing static scanner's cross-file propagation
limit remains visible: a model assessment does not repair its static gate.

Deterministic demonstration (terminal output, no model):

```sh
invscan examples/investigation/context-tools --scans EXEC-05
```

Optional Codex review, with budgets suitable for this one-control fixture:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 \
  --judge-cli codex --analyst-investigation-rounds 2 \
  --analyst-batch-size 1 --analyst-max-calls 3 \
  --analyst-time-budget 900 --judge-timeout 300 \
  --report ./context-review --pdf
```

There is one separate finding-triage request plus at most three control-review
requests. The model may conclude immediately, request one or two context rounds,
or return uncertainty. A live run's actual requests, exact source citations,
structured risk/counterevidence analysis, and denials must be recorded before
claiming that it investigated the predicate. Even correct fixture advice does
not establish a measured real-world true-positive rate.
