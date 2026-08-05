# Security Policy

Tractrix is an XML parser, which means it exists to process untrusted input
by definition. Parser bugs — malformed-input panics, entity-expansion
denial-of-service, XXE-class issues, well-formedness/validation bypasses —
are taken seriously here. If you've found one, please report it privately
rather than opening a public issue.

## Supported versions

Tractrix is pre-1.0. Only the most recently published release on
[crates.io](https://crates.io/crates/tractrix) receives fixes; there are no
maintained older branches. If you're not on the latest version, please
upgrade before reporting — the issue may already be fixed.

## Reporting a vulnerability

Preferred: use GitHub's private vulnerability reporting for this repository
([cpkb-bluezoo/tractrix](https://github.com/cpkb-bluezoo/tractrix/security/advisories/new))
— it opens a private advisory visible only to maintainers until a fix is
ready.

If that isn't available to you, email **dog@gnu.org** with a description of
the issue and, if possible, a minimal reproducing input.

Please include:
- The affected version (or commit).
- The `FeatureSet` configuration in use, if relevant (many issues are
  configuration-dependent — see
  [Security defaults](https://cpkb-bluezoo.github.io/tractrix/security.html)
  for what's on/off by default).
- A minimal reproducing document or test case.
- The impact you'd expect (panic/DoS, memory issue, XXE, validation bypass,
  etc.).

## What's in scope

Bugs in the parser's own handling of adversarial input: crashes or panics
on malformed XML, entity-expansion amplification that isn't caught by
`entity_expansion_limit`, external-entity access that bypasses
`external_general_entities`/`external_parameter_entities`/
`access_external_dtd`, or any other way untrusted input could cause
behavior beyond "reject it as not well-formed / not valid." General
well-formedness or conformance bugs that don't have security impact are
better filed as regular
[issues](https://github.com/cpkb-bluezoo/tractrix/issues).

## Response

This is a small project maintained on a best-effort basis — there's no
formal SLA, but reports are taken seriously and acknowledged as soon as
possible. Please give us reasonable time to release a fix before any public
disclosure.
