package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"go.yaml.in/yaml/v4"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func runCLI(t *testing.T, args []string, stdin string, random []byte) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(args, strings.NewReader(stdin), &stdout, &stderr, bytes.NewReader(random))
	return stdout.String(), stderr.String(), err
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func requireSCRAMVector(t *testing.T, verifier string) {
	t.Helper()
	parts := strings.Split(verifier, "$")
	if len(parts) != 3 || parts[0] != "SCRAM-SHA-256" {
		t.Fatalf("invalid SCRAM verifier %q", verifier)
	}
	parameterAndSalt := strings.Split(parts[1], ":")
	keys := strings.Split(parts[2], ":")
	if len(parameterAndSalt) != 2 || parameterAndSalt[0] != "4096" || len(keys) != 2 {
		t.Fatalf("invalid SCRAM verifier fields %q", verifier)
	}
	if parameterAndSalt[1] != "W22ZaJ0SNY7soEsUEjb6gQ==" {
		t.Fatalf("salt = %q, want supplied fixed vector", parameterAndSalt[1])
	}
	storedKey, err := base64.StdEncoding.DecodeString(keys[0])
	requireNoError(t, err)
	serverKey, err := base64.StdEncoding.DecodeString(keys[1])
	requireNoError(t, err)
	if got := hex.EncodeToString(storedKey); got != "586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6" {
		t.Fatalf("StoredKey = %s", got)
	}
	if got := hex.EncodeToString(serverKey); got != "c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5" {
		t.Fatalf("ServerKey = %s", got)
	}
}

func saltFromSCRAM(t *testing.T, verifier string) []byte {
	t.Helper()
	parts := strings.Split(verifier, "$")
	if len(parts) != 3 {
		t.Fatalf("invalid SCRAM verifier %q", verifier)
	}
	parameterAndSalt := strings.Split(parts[1], ":")
	if len(parameterAndSalt) != 2 {
		t.Fatalf("invalid SCRAM verifier %q", verifier)
	}
	salt, err := base64.StdEncoding.DecodeString(parameterAndSalt[1])
	requireNoError(t, err)
	return salt
}

func TestRunDefaultYAMLSequenceHasStableFields(t *testing.T) {
	plaintext := strings.Repeat("a", defaultLength)
	random := make([]byte, defaultLength+saltSize)
	stdout, stderr, err := runCLI(t, nil, "", random)
	requireNoError(t, err)
	if stderr != "" {
		t.Fatalf("unexpected diagnostics: %q", stderr)
	}

	sum := sha256.Sum256([]byte(plaintext))
	wantFields := []string{
		"- plaintext: " + plaintext,
		"  sha_256: " + hex.EncodeToString(sum[:]),
		"  scram_sha_256: SCRAM-SHA-256$4096:",
		"  name: \"\"",
	}
	last := -1
	for _, field := range wantFields {
		position := strings.Index(stdout, field)
		if position == -1 {
			t.Fatalf("default YAML missing %q:\n%s", field, stdout)
		}
		if position <= last {
			t.Fatalf("default YAML field order is not stable:\n%s", stdout)
		}
		last = position
	}
}

func TestHelpIncludesRegisteredFlagsAndDefaults(t *testing.T) {
	stdout, stderr, err := runCLI(t, []string{"--help"}, "", nil)
	requireNoError(t, err)
	if stdout != "" {
		t.Fatalf("help wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"Usage: pwd_gen [options] [password]",
		"-alphabet string",
		"-bits int",
		"-count int",
		"-emit string",
		"-format string",
		"-length int",
		"-scram-iterations int",
		"-wordlist string",
		"-version",
		"(default 32)",
		"(default \"safe\")",
		"Positional passwords can be exposed",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("help omitted %q:\n%s", want, stderr)
		}
	}
}

func TestVersionWritesOnlyTheBuildVersion(t *testing.T) {
	stdout, stderr, err := runCLI(t, []string{"--version"}, "", nil)
	requireNoError(t, err)
	if stdout != version+"\n" || stderr != "" {
		t.Fatalf("version output/diagnostics = %q/%q", stdout, stderr)
	}
}

func TestRunFormatsAndClickHouseSHA256(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	requireNoError(t, err)

	stdout, stderr, err := runCLI(t, []string{"--format", "json", "--emit", "plaintext,sha256,name", "--name", "", "pencil"}, "", salt)
	requireNoError(t, err)
	if stderr != "" {
		t.Fatalf("unexpected diagnostics: %q", stderr)
	}
	var jsonResult map[string]string
	requireNoError(t, json.Unmarshal([]byte(stdout), &jsonResult))
	if got := jsonResult["plaintext"]; got != "pencil" {
		t.Fatalf("plaintext = %q", got)
	}
	sum := sha256.Sum256([]byte("pencil"))
	if got, want := jsonResult["sha_256"], hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sha_256 = %q, want lowercase ClickHouse-compatible SHA-256 %q", got, want)
	}
	if _, found := jsonResult["scram_sha_256"]; found {
		t.Fatalf("JSON selected an unrequested SCRAM field: %s", stdout)
	}
	if got := jsonResult["name"]; got != "" {
		t.Fatalf("selected empty name = %q", got)
	}

	stdout, _, err = runCLI(t, []string{"--format", "plain", "pencil"}, "", salt)
	requireNoError(t, err)
	if stdout != "pencil\n" {
		t.Fatalf("plain output = %q", stdout)
	}

	stdout, _, err = runCLI(t, []string{"--format", "SCRAM", "pencil"}, "", salt)
	requireNoError(t, err)
	requireSCRAMVector(t, strings.TrimSuffix(stdout, "\n"))
}

func TestRunStdinAndInputConflicts(t *testing.T) {
	stdout, stderr, err := runCLI(t, []string{"--stdin", "--format", "plain"}, "pencil\r\n", make([]byte, saltSize))
	requireNoError(t, err)
	if stdout != "pencil\n" || stderr != "" {
		t.Fatalf("stdin output/diagnostics = %q/%q", stdout, stderr)
	}

	for _, args := range [][]string{
		{"--stdin", "--prefix", "fixed"},
		{"--stdin", "pencil"},
	} {
		_, _, err := runCLI(t, args, "pencil\n", make([]byte, saltSize))
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") && !strings.Contains(err.Error(), "only valid for generated passwords") {
			t.Fatalf("run(%q) error = %v", args, err)
		}
	}

	for _, args := range [][]string{
		{"--length", "0"},
		{"--length", "-1"},
		{"--bits", "8", "--length", "2"},
		{"--yaml-indent", "1"},
		{"--format", "json", "--yaml-indent", "2"},
	} {
		_, _, err := runCLI(t, args, "", nil)
		if err == nil {
			t.Fatalf("run(%q) accepted invalid configuration", args)
		}
	}
}

func TestLengthBitsAlphabetAndGroupedAffixes(t *testing.T) {
	if got, err := lengthForBits(11, len(alphabetPresets["hex"])); err != nil || got != 3 {
		t.Fatalf("lengthForBits(11, 16) = %d, %v; want 3, nil", got, err)
	}
	if got, err := lengthForBits(128, len(alphabetPresets["base64url"])); err != nil || got != 22 {
		t.Fatalf("lengthForBits(128, 64) = %d, %v; want 22, nil", got, err)
	}

	stdout, _, err := runCLI(t, []string{"--bits", "11", "--alphabet", "hex", "--format", "plain"}, "", make([]byte, 3+saltSize))
	requireNoError(t, err)
	if stdout != "000\n" {
		t.Fatalf("rounded bits output = %q", stdout)
	}

	alphabet, err := selectedAlphabet(config{chars: "abcd", exclude: "bd"})
	requireNoError(t, err)
	if alphabet != "ac" {
		t.Fatalf("filtered alphabet = %q", alphabet)
	}
	if err := validateASCIIAlphabet("test", "aab"); err == nil {
		t.Fatal("duplicate alphabet was accepted")
	}
	if err := validateASCIIAlphabet("test", "aé"); err == nil {
		t.Fatal("non-ASCII alphabet was accepted")
	}

	stdout, _, err = runCLI(t, []string{"--chars", "ab", "--length", "5", "--group-size", "2", "--group-separator", ":", "--prefix", "pre", "--suffix", "post", "--format", "plain"}, "", make([]byte, 5+saltSize))
	requireNoError(t, err)
	if stdout != "preaa:aa:apost\n" {
		t.Fatalf("grouped affix output = %q", stdout)
	}
}

func TestCountUsesFreshSCRAMSalts(t *testing.T) {
	random := make([]byte, 0, 2+2*saltSize)
	random = append(random, 0)
	for i := 0; i < saltSize; i++ {
		random = append(random, byte(i))
	}
	random = append(random, 0)
	for i := 0; i < saltSize; i++ {
		random = append(random, byte(i+16))
	}
	stdout, _, err := runCLI(t, []string{"--count", "2", "--length", "1", "--format", "json"}, "", random)
	requireNoError(t, err)

	var results []outputResult
	requireNoError(t, json.Unmarshal([]byte(stdout), &results))
	if len(results) != 2 || results[0].SCRAMSHA256 == nil || results[1].SCRAMSHA256 == nil {
		t.Fatalf("count output = %s", stdout)
	}
	firstSalt := saltFromSCRAM(t, *results[0].SCRAMSHA256)
	secondSalt := saltFromSCRAM(t, *results[1].SCRAMSHA256)
	if bytes.Equal(firstSalt, secondSalt) {
		t.Fatalf("count reused SCRAM salt %x", firstSalt)
	}
	if !bytes.Equal(firstSalt, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatalf("first salt = %x", firstSalt)
	}
	if !bytes.Equal(secondSalt, []byte{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}) {
		t.Fatalf("second salt = %x", secondSalt)
	}
}

func TestFixedSCRAMVerifierVector(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	requireNoError(t, err)
	result, err := deriveResult("pencil", "", 4096, emitFields{scram: true}, bytes.NewReader(salt))
	requireNoError(t, err)
	if result.SCRAMSHA256 == nil {
		t.Fatal("SCRAM result was not emitted")
	}
	requireSCRAMVector(t, *result.SCRAMSHA256)
}

func FuzzParseConfig(f *testing.F) {
	f.Add("")
	f.Add("all")
	f.Add("plaintext,sha256,scram,name")
	f.Add("unknown")
	f.Add("--bits=11")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 128 {
			t.Skip()
		}
		value = strings.ToValidUTF8(value, "?")
		_, _, _ = parseConfig([]string{"--emit", value}, nil)
		_, _ = parseEmit(value)
	})
}

func TestRejectsInvalidUTF8SuppliedPassword(t *testing.T) {
	invalid := string([]byte{0xff})
	_, _, err := runCLI(t, []string{invalid}, "", make([]byte, saltSize))
	if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("invalid UTF-8 password error = %v", err)
	}
}

func FuzzArgumentValidation(f *testing.F) {
	f.Add("--length=0", "", "")
	f.Add("--format=unsupported", "", "")
	f.Add("--stdin", "password", "")
	f.Add("--interactive", "--stdin", "")
	f.Add("one", "two", "")
	f.Fuzz(func(t *testing.T, first, second, third string) {
		if len(first)+len(second)+len(third) > 256 {
			t.Skip()
		}
		args := []string{first, second, third}
		validate := func() string {
			cfg, positional, err := parseConfig(args, nil)
			if err != nil {
				return err.Error()
			}
			emit, err := parseEmit(cfg.emit)
			if err != nil {
				return err.Error()
			}
			if err := validateConfig(cfg, positional, emit); err != nil {
				return err.Error()
			}
			return ""
		}
		if firstOutcome, secondOutcome := validate(), validate(); firstOutcome != secondOutcome {
			t.Fatalf("validation was nondeterministic: %q then %q", firstOutcome, secondOutcome)
		}
	})
}

func FuzzAlphabetAndGeneration(f *testing.F) {
	f.Add("ab", "")
	f.Add("abcdefgh", "ace")
	f.Add("aab", "")
	f.Add("é", "")
	f.Fuzz(func(t *testing.T, chars, exclude string) {
		if len(chars) > 64 || len(exclude) > 64 {
			t.Skip()
		}
		cfg := config{chars: chars, exclude: exclude}
		alphabet, err := selectedAlphabet(cfg)
		if err != nil {
			return
		}
		generated, err := generateCharacters(alphabet, 16, 0, "", "", "", zeroReader{})
		requireNoError(t, err)
		if len(generated) != 16 {
			t.Fatalf("generated length = %d", len(generated))
		}
		for i := range generated {
			if !strings.ContainsRune(alphabet, rune(generated[i])) {
				t.Fatalf("generated character %q is outside %q", generated[i], alphabet)
			}
		}
	})
}

func FuzzEncoders(f *testing.F) {
	f.Add("pencil", "")
	f.Add("line\nwith: yaml", "name")
	f.Add("quotes \" and backslash \\\\", "control\x01")
	f.Fuzz(func(t *testing.T, plaintext, name string) {
		if len(plaintext) > 128 || len(name) > 128 {
			t.Skip()
		}
		plaintext = strings.ToValidUTF8(plaintext, "?")
		name = strings.ToValidUTF8(name, "?")
		result := outputResult{
			Plaintext:   new(plaintext),
			SHA256:      new(hex.EncodeToString(sha256.New().Sum(nil))),
			SCRAMSHA256: new("SCRAM-SHA-256$1:AA==$AA==:AA=="),
			Name:        new(name),
		}
		for _, format := range []string{"yaml", "json", "plain", "scram"} {
			var output bytes.Buffer
			requireNoError(t, encodeResults(format, 2, []outputResult{result}, &output))
			if output.Len() == 0 {
				t.Fatalf("%s encoder emitted no output", format)
			}
		}
		var first, second bytes.Buffer
		requireNoError(t, encodeResults("yaml", 2, []outputResult{result}, &first))
		requireNoError(t, encodeResults("yaml", 2, []outputResult{result}, &second))
		if first.String() != second.String() {
			t.Fatalf("YAML output was not deterministic")
		}
		var decoded []map[string]string
		requireNoError(t, yaml.Unmarshal(first.Bytes(), &decoded))
		if len(decoded) != 1 || decoded[0]["plaintext"] != plaintext || decoded[0]["name"] != name {
			t.Fatalf("YAML round-trip = %#v", decoded)
		}
	})
}

func FuzzAffixes(f *testing.F) {
	f.Add("pre", "post", ":")
	f.Add("", "", "-")
	f.Add("[]", "{}", " / ")
	f.Fuzz(func(t *testing.T, prefix, suffix, separator string) {
		if len(prefix) > 64 || len(suffix) > 64 || len(separator) > 32 {
			t.Skip()
		}
		prefix = strings.ToValidUTF8(prefix, "?")
		suffix = strings.ToValidUTF8(suffix, "?")
		separator = strings.ToValidUTF8(separator, "?")
		got, err := generateCharacters("ab", 6, 2, separator, prefix, suffix, zeroReader{})
		requireNoError(t, err)
		want := prefix + "aa" + separator + "aa" + separator + "aa" + suffix
		if got != want {
			t.Fatalf("affixed grouped password = %q, want %q", got, want)
		}
	})
}

func FuzzSCRAM(f *testing.F) {
	f.Add("pencil", []byte{91, 109, 153, 104, 157, 18, 53, 142, 236, 160, 75, 20, 18, 54, 250, 129}, uint16(4095))
	f.Add("", make([]byte, saltSize), uint16(0))
	f.Fuzz(func(t *testing.T, password string, salt []byte, iterations uint16) {
		if len(password) > 128 {
			t.Skip()
		}
		password = strings.ToValidUTF8(password, "?")
		fixedSalt := make([]byte, saltSize)
		copy(fixedSalt, salt)
		count := int(iterations%4096) + 1
		emit := emitFields{scram: true}
		first, err := deriveResult(password, "", count, emit, bytes.NewReader(fixedSalt))
		requireNoError(t, err)
		second, err := deriveResult(password, "", count, emit, bytes.NewReader(fixedSalt))
		requireNoError(t, err)
		if first.SCRAMSHA256 == nil || second.SCRAMSHA256 == nil || *first.SCRAMSHA256 != *second.SCRAMSHA256 {
			t.Fatalf("SCRAM derivation was not deterministic for fixed inputs")
		}
		if len(saltFromSCRAM(t, *first.SCRAMSHA256)) != saltSize {
			t.Fatalf("SCRAM salt length is not %d", saltSize)
		}
	})
}
