# Vendored test fixtures

- `sarif-schema-2.1.0.json`: the official SARIF 2.1.0 JSON schema (OASIS Static Analysis Results Interchange Format TC), used offline by `test/ci-formats.test.ts` to validate `scan --format sarif` output.
  - Source: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json (schema id `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`), retrieved 2026-10-08.
  - SHA-256: c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
  - Copyright OASIS Open. Distributed under the OASIS IPR Policy; see https://www.oasis-open.org/policies-guidelines/ipr/. It is a test fixture only and is not shipped in the package.
