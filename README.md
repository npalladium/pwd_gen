# Password Generator

Generate cryptographically random passwords and emit the forms needed for
ClickHouse and SCRAM-SHA-256 configuration. It requires Go 1.27 or newer.
Release builds support Linux (`amd64`, `arm`, `arm64`), Darwin (`amd64`,
`arm64`), and Windows (`amd64`, `arm64`) with CGO disabled.

## Build

```sh
make build
./pwd_gen
```

`make encrypt` remains a short alias for `make build`. `make test` runs the
test suite; `make check` runs tests and `go vet`.

## Input and generation

Without an input flag, the program generates a password. It also accepts
exactly one non-empty positional password, `--interactive` for a hidden
terminal prompt, or `--stdin` for supplied input. These modes are mutually
exclusive. Supplied passwords must be valid UTF-8.

Do not put real passwords in positional arguments: shells may retain them in
history and other local users or processes may be able to inspect command-line
arguments. Prefer `--interactive` or `--stdin`. Prompts and diagnostics are
written to standard error; selected output is written only to standard output.

Random characters and Diceware words are selected with unbiased cryptographic
randomness. `--length` and `--bits` describe only the random component; fixed
prefixes, suffixes, and grouping separators add no entropy. The complete
emitted plaintext—including those fixed additions and separators—is the value
hashed and used for SCRAM derivation.

### Generation flags

| Flag | Meaning |
| --- | --- |
| `--length N` | Number of random characters; positive, default `32`. |
| `--bits N` | Request a positive random-component entropy target. It uses `ceil(bits / log2(alphabet size))` characters and conflicts with an explicitly supplied `--length`. |
| `--alphabet NAME` | Select one of `safe`, `alnum`, `crockford32`, `rfc4648-base32`, `base64url`, `hex`, or `printable`. |
| `--chars TEXT` | Select an explicit character alphabet. |
| `--exclude TEXT` | Remove characters from the selected alphabet. The resulting alphabet must be non-empty, unique, and printable ASCII. |
| `--group-size N` | Group generated characters in positive-sized groups. |
| `--group-separator TEXT` | Text inserted between character groups. |
| `--prefix TEXT` | Fixed text prepended to generated plaintext. |
| `--suffix TEXT` | Fixed text appended to generated plaintext. |
| `--words N` | Generate a positive number of Diceware words; requires `--wordlist`. |
| `--wordlist FILE` | External Diceware wordlist. Non-empty, unique UTF-8 lines are used after CRLF trimming; blank lines are ignored. |
| `--separator TEXT` | Join generated Diceware words; valid only with `--words`. |
| `--count N` | Generate a positive number of independently salted records. Valid only for generated input. |
`printable` includes shell-significant punctuation. Quote it as a flag value and use the structured output formats when moving generated values through shell tooling.

`--alphabet` and `--chars` are alternative ways to choose an alphabet and
cannot be used together when `--alphabet` is explicitly supplied. `--exclude`
applies to the selected preset or explicit alphabet; both the selected alphabet
and exclusion string must contain unique printable ASCII bytes, and exclusion
must leave a non-empty alphabet. Character-only options (`--alphabet`, `--chars`,
`--exclude`, `--length`, `--bits`, `--group-size`, and `--group-separator`)
cannot be mixed with Diceware's `--words`; `--wordlist` requires `--words`, and
an explicit `--separator` is invalid without it. Grouping options are for
generated character output.

Wordlist entries are trimmed only for CRLF line endings: blank lines are
skipped, and every remaining entry must be non-empty, valid UTF-8, and unique.
The selected words and separators are part of the emitted plaintext.
For Diceware output, the program reports `N * log2(unique_word_count)` entropy in bits on standard error.

The `--bits`/`--length` conflict applies only when `--length` was explicitly
provided; the default length does not prevent using `--bits`. All numeric
limits described as positive reject zero and negative values. `--count` is
restricted to generated mode and cannot be used with a supplied password,
`--interactive`, or `--stdin`. Generation-only flags likewise conflict with
those supplied-input modes.

All text-valued flags and supplied input are expected to be valid UTF-8.
`--alphabet` and `--chars` configure a byte alphabet; presets are shown in the
generation table above. A wordlist is read locally; the program does not
download wordlists at runtime.

### Input and output flags

| Flag | Meaning |
| --- | --- |
| `--interactive` | Read one password from a hidden terminal prompt. |
| `--stdin` | Read a supplied password from standard input. |
| `--format FORMAT` | Output format: `yaml` (default), `json`, `plain`, or `scram`. |
| `--name TEXT` | Record name. In structured output, an empty name is still emitted when selected. |
| `--emit FIELDS` | Comma-separated structured fields: `plaintext`, `sha256`, `scram`, `name`, or `all` (the default). |
| `--yaml-indent N` | YAML indentation, default `2`, supported range `2`–`9`; valid only with `--format yaml`. |
| `--scram-iterations N` | Positive SCRAM-SHA-256 iteration count, default `4096`. |

`--emit` selects fields only for YAML and JSON. `plain` and `scram` retain
their one-value contracts and reject a non-default `--emit` selection.

## Formats and compatibility

YAML is the default and always emits a sequence, including a one-record result.
Its default item field order is `plaintext`, `sha_256`, `scram_sha_256`, then
`name`; the empty `name` is deliberately present. This preserves the existing
YAML shape.

JSON emits an object for one record and an array for multiple records. Both
structured formats omit fields not selected by `--emit`; their canonical keys
are `plaintext`, `sha_256`, `scram_sha_256`, and `name`.

`plain` emits the plaintext password. `scram` emits the padded standard-Base64
SCRAM-SHA-256 value compatible with the existing output. Each generated result
uses a fresh salt.

`sha_256` is the lowercase hexadecimal SHA-256 of the exact emitted UTF-8
plaintext. It exists for ClickHouse configuration compatibility and is **not**
a password-verification hash. Use the SCRAM output where SCRAM-SHA-256 is
required; protect every emitted secret and derived value appropriately.

## Examples

```sh
# Default YAML sequence with all compatibility fields.
./pwd_gen --name production-api

# A 128-bit random component using the safe alphabet.
./pwd_gen --bits 128 --alphabet safe --format json --emit plaintext,sha256,name

# Character groups, with deterministic decorations included in all derivations.
./pwd_gen --length 24 --group-size 4 --group-separator=- --prefix 'svc_' --suffix '_2026'

# Six Diceware words from a local wordlist.
./pwd_gen --words 6 --wordlist ./diceware.txt --separator=-

# Produce only a SCRAM value for a password supplied through stdin.
printf '%s' 'replace-this-example-secret' | ./pwd_gen --stdin --format scram

# Generate several independently salted structured records.
./pwd_gen --count 3 --format json --name worker
```

## Deliberately excluded

The program does not provide clipboard support, runtime wordlist downloads, a
template language, BIP-39 or pronounceable-password generation, or additional
password-storage algorithms.

## License

Licensed under the [MIT](https://opensource.org/license/mit/) license. This is
forked from [Taishi Kasuga's scram-sha-256](https://github.com/supercaracal/scram-sha-256);
the original license is available
[here](https://github.com/supercaracal/scram-sha-256/blob/master/LICENSE).
