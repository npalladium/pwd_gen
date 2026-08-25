# Password generator backlog implementation

## Scope

Keep runtime implementation in `main.go`. Preserve the default YAML sequence and its field order (`plaintext`, `sha_256`, `scram_sha_256`, `name`), including an emitted empty `name`. The `sha_256` field remains the lowercase SHA-256 value needed by ClickHouse configuration; it is not a password-verification hash.

Items explicitly marked out of scope remain excluded: no clipboard support, runtime wordlist download, template language, BIP-39/pronounceable passwords, or additional password-storage algorithms.

## CLI contract

- Input modes are exclusive: generated (default), one non-empty positional password, `--interactive`, or `--stdin`. Supplied values must be valid UTF-8. Prompts and diagnostics use stderr; stdout is reserved for selected output.
- Character generation accepts a positive `--length` (default 32) or positive `--bits`, never both when length is explicit. Both describe the random component only; requested bits rounds up using `ceil(bits/log2(alphabet size))`.
- `--count` generates independently salted results and is restricted to generated modes.
- `--alphabet`, `--chars`, and `--exclude` select a non-empty, unique ASCII alphabet. Presets are `safe`, `alnum`, `crockford32`, `rfc4648-base32`, `base64url`, `hex`, and `printable`.
- `--prefix` and `--suffix` are fixed, zero-entropy text. Group separators are likewise deterministic and are included in the emitted plaintext and derivations. Diceware uses `--words`, required `--wordlist`, and `--separator` with unbiased choice from a validated external wordlist.
- Supported formats are YAML (default), JSON, plain, and SCRAM. `--emit` selects fields for structured formats; plain and SCRAM retain their single-value contracts. YAML indentation is configurable only for YAML.

## Implementation

1. Replace global flag parsing with a `flag.FlagSet` parser and validated configuration.
2. Split parsing, validation, input acquisition, character/Diceware generation, SHA/SCRAM derivation, and output encoding into focused functions in `main.go`.
3. Use injected readers/writers/random sources. Use standard-library `crypto/pbkdf2`, `crypto/sha256.Sum256`, `base64.StdEncoding.EncodeToString`, and `golang.org/x/term`.
4. Use `go.yaml.in/yaml/v4` with configured indentation while retaining the compatibility sequence shape.
5. Do not use `crypto/rand.Text` for RFC 4648 Base32: its fixed encoding cannot honor the CLI's requested length, bits, exclusion, grouping, or custom-alphabet contracts; the validated unbiased selector remains the common implementation.
6. Upgrade module metadata to Go 1.27 and remove obsolete dependencies.
7. Add deterministic unit, schema, and fuzz tests in `main_test.go`; update README and Makefile.
8. Generate `--help` from the `flag.FlagSet` metadata so every flag, default, and concise semantic constraint stays synchronized with parsing.

## Verification

Run formatter, `go mod tidy`, targeted and full tests, vet, build, and CLI smoke tests. Exercise every output format, supplied stdin input, entropy conversion, and Diceware with a local wordlist. Verify cross-compilation for the documented supported target set through `go build`.
