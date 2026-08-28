<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Contract Catalog

Files in this directory are the normative description of the current repository. They describe
what must remain true, not how the implementation evolved.

| Contract | Exclusive ownership |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Components, data flow, lifecycle, global invariants |
| [`PUBLIC_API.md`](PUBLIC_API.md) | Exact Android public API coverage and normalization semantics |
| [`PROBE.md`](PROBE.md) | Independent detector applications, IDs, records, verdicts |
| [`AUTOMATION.md`](AUTOMATION.md) | Make interface, container boundary, toolchain, artifacts |
| [`VALIDATION.md`](VALIDATION.md) | Supported runtime identity and accepted evidence |
| [`SECURITY.md`](SECURITY.md) | Caller boundary, exclusions, fail-open behavior, privacy |

Every normative assertion uses a permanent three-letter identifier and this shape:

```text
### `ABC-001` - Short title
**Contract:** A testable statement using MUST, MUST NOT, or MAY.
**Evidence:** The implementation, test, or Make target that verifies it.
```

Identifiers remain stable while their current wording may be refined. A changed behavior updates
the owning assertion and its evidence in the same patch. Maintenance documents MAY summarize only
the command-critical precondition or outcome needed to execute a cited assertion; they MUST NOT
create an independent behavior definition, silently broaden it, or override the owning contract.
`make docs-check` validates document presence, Markdown structure, identifier uniqueness, assertion
shape, links from `AGENTS.md`, and the complete Make target inventory.

When facts conflict, use this precedence: current packaged/runtime behavior, current source and
tests, then these contracts. Device observations demonstrate only the tested session and never
establish model/build compatibility. Official Android sources define API intent but do not replace
runtime proof. Correct every affected layer together as required by
`AGENTS.md`; never preserve a known mismatch for documentation compatibility.
