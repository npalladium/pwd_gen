package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v4"
	"golang.org/x/term"
)

const (
	saltSize          = 16
	digestLen         = sha256.Size
	defaultLength     = 32
	defaultIterations = 4096
	defaultIndent     = 2

	maxCount          = 1000
	maxRandomLength   = 4096
	maxBits           = 32768
	maxWords          = 1024
	maxIterations     = 1_000_000
	maxDerivationWork = 10_000_000
	maxInputBytes     = 1 << 20
	maxWordlistBytes  = 1 << 20
	maxWordlistWords  = 100_000
	minYAMLIndent     = 2
	maxYAMLIndent     = 9
)

var alphabetPresets = map[string]string{
	"safe":           "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ2346789",
	"alnum":          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"crockford32":    "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
	"rfc4648-base32": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
	"base64url":      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
	"hex":            "0123456789abcdef",
	"printable":      "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
}

var (
	clientRawKey = []byte("Client Key")
	serverRawKey = []byte("Server Key")
	version      = "dev"
)

type config struct {
	length          int
	bits            int
	interactive     bool
	stdin           bool
	format          string
	name            string
	version         bool
	count           int
	emit            string
	yamlIndent      int
	scramIterations int
	alphabet        string
	chars           string
	exclude         string
	groupSize       int
	groupSeparator  string
	prefix          string
	suffix          string
	words           int
	wordlist        string
	separator       string
	explicit        map[string]bool
}

type emitFields struct {
	plaintext bool
	sha256    bool
	scram     bool
	name      bool
}

// outputResult deliberately uses pointers: a selected empty name is emitted,
// while an unselected field is absent from structured output.
type outputResult struct {
	Plaintext   *string `yaml:"plaintext,omitempty" json:"plaintext,omitempty"`
	SHA256      *string `yaml:"sha_256,omitempty" json:"sha_256,omitempty"`
	SCRAMSHA256 *string `yaml:"scram_sha_256,omitempty" json:"scram_sha_256,omitempty"`
	Name        *string `yaml:"name,omitempty" json:"name,omitempty"`
}

type yamlString string

func (value yamlString) MarshalYAML() (any, error) {
	node := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(value)}
	if strings.ContainsAny(string(value), "\t\r\n") || strings.HasPrefix(string(value), " ") || strings.HasSuffix(string(value), " ") {
		node.Style = yaml.DoubleQuotedStyle
	}
	return node, nil
}

type yamlOutputResult struct {
	Plaintext   *yamlString `yaml:"plaintext,omitempty"`
	SHA256      *yamlString `yaml:"sha_256,omitempty"`
	SCRAMSHA256 *yamlString `yaml:"scram_sha_256,omitempty"`
	Name        *yamlString `yaml:"name,omitempty"`
}

func (result outputResult) MarshalYAML() (any, error) {
	return yamlOutputResult{
		Plaintext:   yamlStringValue(result.Plaintext),
		SHA256:      yamlStringValue(result.SHA256),
		SCRAMSHA256: yamlStringValue(result.SCRAMSHA256),
		Name:        yamlStringValue(result.Name),
	}, nil
}

func yamlStringValue(value *string) *yamlString {
	if value == nil {
		return nil
	}
	return new(yamlString(*value))
}

type terminalInput interface {
	Fd() uintptr
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, rand.Reader); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, randomReader io.Reader) error {
	cfg, positional, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if cfg.version {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if randomReader == nil {
		return errors.New("random reader is required")
	}

	cfg.format = strings.ToLower(cfg.format)
	emit, err := parseEmit(cfg.emit)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg, positional, emit); err != nil {
		return err
	}

	var words []string
	var alphabet string
	if isGeneratedMode(cfg, positional) {
		if cfg.words > 0 {
			words, err = readWordlist(cfg.wordlist)
		} else {
			alphabet, err = selectedAlphabet(cfg)
		}
		if err != nil {
			return err
		}
	}
	if cfg.words > 0 {
		if _, err := fmt.Fprintf(stderr, "entropy: %.2f bits\n", float64(cfg.words)*math.Log2(float64(len(words)))); err != nil {
			return fmt.Errorf("report Diceware entropy: %w", err)
		}
	}

	results := make([]outputResult, 0, cfg.count)
	for range cfg.count {
		plaintext, err := acquirePassword(cfg, positional, stdin, stderr, randomReader, alphabet, words)
		if err != nil {
			return err
		}
		result, err := deriveResult(plaintext, cfg.name, cfg.scramIterations, emit, randomReader)
		if err != nil {
			return err
		}
		results = append(results, result)
	}
	return encodeResults(cfg.format, cfg.yamlIndent, results, stdout)
}

func parseConfig(args []string, helpOutput io.Writer) (config, []string, error) {
	cfg := config{
		length:          defaultLength,
		format:          "yaml",
		count:           1,
		emit:            "all",
		yamlIndent:      defaultIndent,
		scramIterations: defaultIterations,
		alphabet:        "safe",
		groupSeparator:  "-",
		separator:       "-",
		explicit:        make(map[string]bool),
	}
	if helpOutput == nil {
		helpOutput = io.Discard
	}
	fs := flag.NewFlagSet("password-generator", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { writeUsage(helpOutput, fs) }
	fs.IntVar(&cfg.length, "length", defaultLength, "random-character length; conflicts with an explicit --bits")
	fs.IntVar(&cfg.bits, "bits", 0, "minimum random-character entropy; conflicts with an explicit --length")
	fs.BoolVar(&cfg.interactive, "interactive", false, "read one non-empty UTF-8 password without echo")
	fs.BoolVar(&cfg.stdin, "stdin", false, "read one non-empty UTF-8 password from standard input")
	fs.StringVar(&cfg.format, "format", "yaml", "output: yaml, json, plain, or scram")
	fs.StringVar(&cfg.name, "name", "", "record name; emitted even when empty in structured output")
	fs.BoolVar(&cfg.version, "version", false, "print the build version and exit")
	fs.IntVar(&cfg.count, "count", 1, "independent generated passwords; unavailable for supplied input")
	fs.StringVar(&cfg.emit, "emit", "all", "structured fields: plaintext, sha256, scram, name, or all")
	fs.IntVar(&cfg.yamlIndent, "yaml-indent", defaultIndent, "YAML indentation from 2 through 9; YAML output only")
	fs.IntVar(&cfg.scramIterations, "scram-iterations", defaultIterations, "SCRAM-SHA-256 iterations")
	fs.StringVar(&cfg.alphabet, "alphabet", "safe", "preset: safe, alnum, crockford32, rfc4648-base32, base64url, hex, or printable")
	fs.StringVar(&cfg.chars, "chars", "", "custom unique printable-ASCII alphabet; conflicts with explicit --alphabet")
	fs.StringVar(&cfg.exclude, "exclude", "", "unique printable-ASCII characters removed from the alphabet")
	fs.IntVar(&cfg.groupSize, "group-size", 0, "random characters in each output group; requires --group-separator when set")
	fs.StringVar(&cfg.groupSeparator, "group-separator", "-", "deterministic separator between character groups")
	fs.StringVar(&cfg.prefix, "prefix", "", "fixed generated-password prefix; adds no entropy")
	fs.StringVar(&cfg.suffix, "suffix", "", "fixed generated-password suffix; adds no entropy")
	fs.IntVar(&cfg.words, "words", 0, "Diceware words; requires --wordlist and conflicts with character options")
	fs.StringVar(&cfg.wordlist, "wordlist", "", "local unique UTF-8 Diceware wordlist; requires --words")
	fs.StringVar(&cfg.separator, "separator", "-", "deterministic separator for --words")
	if err := fs.Parse(args); err != nil {
		return config{}, nil, err
	}
	fs.Visit(func(f *flag.Flag) { cfg.explicit[f.Name] = true })
	return cfg, fs.Args(), nil
}

func writeUsage(output io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(output, "Usage: pwd_gen [options] [password]")
	fmt.Fprintln(output, "Generate a password or process exactly one supplied password.")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Input modes are mutually exclusive: a positional password, --interactive, --stdin, or generated output.")
	fmt.Fprintln(output, "Lengths and bits apply only to the random component; prefixes, suffixes, and separators add no entropy.")
	fmt.Fprintln(output, "stdout contains only selected output. Prompts, diagnostics, and Diceware entropy use stderr.")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Options:")
	previousOutput := flags.Output()
	flags.SetOutput(output)
	flags.PrintDefaults()
	flags.SetOutput(previousOutput)
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Positional passwords can be exposed in shell history and process listings; prefer --interactive or --stdin.")
}

func validateConfig(cfg config, positional []string, emit emitFields) error {
	cfg.format = strings.ToLower(cfg.format)
	if cfg.format != "yaml" && cfg.format != "json" && cfg.format != "plain" && cfg.format != "scram" {
		return fmt.Errorf("unsupported --format %q", cfg.format)
	}
	if len(positional) > 1 {
		return errors.New("at most one positional password is allowed")
	}
	if len(positional) == 1 {
		if positional[0] == "" {
			return errors.New("positional password must not be empty")
		}
		if err := validateText("positional password", positional[0]); err != nil {
			return err
		}
	}

	inputModes := boolToInt(len(positional) == 1) + boolToInt(cfg.interactive) + boolToInt(cfg.stdin)
	if inputModes > 1 {
		return errors.New("positional, --interactive, and --stdin inputs are mutually exclusive")
	}
	if cfg.count < 1 || cfg.count > maxCount {
		return fmt.Errorf("--count must be between 1 and %d", maxCount)
	}
	if inputModes > 0 && cfg.explicit["count"] {
		return errors.New("--count is available only for generated passwords")
	}

	if cfg.length < 1 || cfg.length > maxRandomLength {
		return fmt.Errorf("--length must be between 1 and %d", maxRandomLength)
	}
	if cfg.bits < 0 || cfg.bits > maxBits || (cfg.explicit["bits"] && cfg.bits == 0) {
		return fmt.Errorf("--bits must be between 1 and %d when supplied", maxBits)
	}
	if cfg.explicit["bits"] && cfg.explicit["length"] {
		return errors.New("--bits conflicts with an explicitly supplied --length")
	}
	if cfg.groupSize < 0 || cfg.groupSize > maxRandomLength {
		return fmt.Errorf("--group-size must be between 0 and %d", maxRandomLength)
	}
	if cfg.explicit["group-separator"] && cfg.groupSize == 0 {
		return errors.New("--group-separator requires --group-size")
	}
	if cfg.words < 0 || cfg.words > maxWords || (cfg.explicit["words"] && cfg.words == 0) {
		return fmt.Errorf("--words must be between 1 and %d when supplied", maxWords)
	}
	if cfg.words > 0 {
		if cfg.wordlist == "" {
			return errors.New("--words requires --wordlist")
		}
		for _, name := range []string{"length", "bits", "alphabet", "chars", "exclude", "group-size", "group-separator"} {
			if cfg.explicit[name] {
				return fmt.Errorf("--%s is only valid for character generation", name)
			}
		}
	} else {
		if cfg.explicit["wordlist"] {
			return errors.New("--wordlist requires --words")
		}
		if cfg.explicit["separator"] {
			return errors.New("--separator requires --words")
		}
	}
	if cfg.explicit["alphabet"] && cfg.explicit["chars"] {
		return errors.New("--alphabet conflicts with --chars")
	}
	if inputModes > 0 {
		for _, name := range []string{"length", "bits", "alphabet", "chars", "exclude", "group-size", "group-separator", "prefix", "suffix", "words", "wordlist", "separator"} {
			if cfg.explicit[name] {
				return fmt.Errorf("--%s is only valid for generated passwords", name)
			}
		}
	}

	cfg.format = strings.ToLower(cfg.format)
	if cfg.format != "yaml" && cfg.format != "json" && cfg.format != "plain" && cfg.format != "scram" {
		return fmt.Errorf("unsupported --format %q", cfg.format)
	}
	if cfg.format != "yaml" && cfg.explicit["yaml-indent"] {
		return errors.New("--yaml-indent is valid only with --format yaml")
	}
	if cfg.yamlIndent < minYAMLIndent || cfg.yamlIndent > maxYAMLIndent {
		return fmt.Errorf("--yaml-indent must be between %d and %d", minYAMLIndent, maxYAMLIndent)
	}
	if (cfg.format == "plain" || cfg.format == "scram") && !emit.all() {
		return fmt.Errorf("--emit may not select fields with --format %s", cfg.format)
	}
	if cfg.scramIterations < 1 || cfg.scramIterations > maxIterations {
		return fmt.Errorf("--scram-iterations must be between 1 and %d", maxIterations)
	}
	if cfg.count > maxDerivationWork/cfg.scramIterations {
		return fmt.Errorf("--count and --scram-iterations exceed %d total iterations", maxDerivationWork)
	}
	for _, value := range []struct {
		name string
		text string
	}{
		{"--format", cfg.format},
		{"--name", cfg.name},
		{"--prefix", cfg.prefix},
		{"--suffix", cfg.suffix},
		{"--group-separator", cfg.groupSeparator},
		{"--separator", cfg.separator},
	} {
		if err := validateText(value.name, value.text); err != nil {
			return err
		}
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func validateText(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", name)
	}
	if len(value) > maxInputBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxInputBytes)
	}
	return nil
}

func parseEmit(value string) (emitFields, error) {
	if value == "" {
		return emitFields{}, errors.New("--emit must select at least one field")
	}
	var fields emitFields
	for _, field := range strings.Split(value, ",") {
		switch strings.ToLower(field) {
		case "plaintext":
			fields.plaintext = true
		case "sha256":
			fields.sha256 = true
		case "scram":
			fields.scram = true
		case "name":
			fields.name = true
		case "all":
			fields = emitFields{plaintext: true, sha256: true, scram: true, name: true}
		default:
			return emitFields{}, fmt.Errorf("unknown --emit field %q", field)
		}
	}
	return fields, nil
}

func (fields emitFields) all() bool {
	return fields.plaintext && fields.sha256 && fields.scram && fields.name
}

func isGeneratedMode(cfg config, positional []string) bool {
	return len(positional) == 0 && !cfg.interactive && !cfg.stdin
}

func selectedAlphabet(cfg config) (string, error) {
	alphabet := cfg.chars
	if alphabet == "" {
		var ok bool
		alphabet, ok = alphabetPresets[cfg.alphabet]
		if !ok {
			return "", fmt.Errorf("unknown --alphabet %q", cfg.alphabet)
		}
	}
	if err := validateASCIIAlphabet("selected alphabet", alphabet); err != nil {
		return "", err
	}
	if cfg.exclude == "" {
		return alphabet, nil
	}
	if err := validateASCIIAlphabet("--exclude", cfg.exclude); err != nil {
		return "", err
	}
	excluded := make(map[byte]struct{}, len(cfg.exclude))
	for i := 0; i < len(cfg.exclude); i++ {
		excluded[cfg.exclude[i]] = struct{}{}
	}
	filtered := make([]byte, 0, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		if _, found := excluded[alphabet[i]]; !found {
			filtered = append(filtered, alphabet[i])
		}
	}
	if len(filtered) == 0 {
		return "", errors.New("--exclude removes every character from the selected alphabet")
	}
	return string(filtered), nil
}

func validateASCIIAlphabet(name, alphabet string) error {
	if alphabet == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	seen := [128]bool{}
	for i := 0; i < len(alphabet); i++ {
		ch := alphabet[i]
		if ch < 0x21 || ch > 0x7e {
			return fmt.Errorf("%s must contain only printable ASCII characters", name)
		}
		if seen[ch] {
			return fmt.Errorf("%s must not contain duplicate characters", name)
		}
		seen[ch] = true
	}
	return nil
}

func readWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read wordlist: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxWordlistBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read wordlist: %w", err)
	}
	if len(contents) > maxWordlistBytes {
		return nil, fmt.Errorf("wordlist exceeds %d bytes", maxWordlistBytes)
	}
	if !utf8.Valid(contents) {
		return nil, errors.New("wordlist must be valid UTF-8")
	}
	words := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, exists := seen[line]; exists {
			return nil, fmt.Errorf("wordlist contains duplicate word %q", line)
		}
		if len(words) == maxWordlistWords {
			return nil, fmt.Errorf("wordlist exceeds %d words", maxWordlistWords)
		}
		seen[line] = struct{}{}
		words = append(words, line)
	}
	if len(words) == 0 {
		return nil, errors.New("wordlist contains no words")
	}
	return words, nil
}

func acquirePassword(cfg config, positional []string, stdin io.Reader, stderr io.Writer, randomReader io.Reader, alphabet string, words []string) (string, error) {
	if len(positional) == 1 {
		return positional[0], nil
	}
	if cfg.stdin {
		if stdin == nil {
			return "", errors.New("stdin reader is required")
		}
		contents, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		if len(contents) > maxInputBytes {
			return "", fmt.Errorf("stdin password exceeds %d bytes", maxInputBytes)
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(contents), "\n"), "\r")
		if password == "" {
			return "", errors.New("stdin password must not be empty")
		}
		if err := validateText("stdin password", password); err != nil {
			return "", err
		}
		return password, nil
	}
	if cfg.interactive {
		terminal, ok := stdin.(terminalInput)
		if !ok {
			return "", errors.New("--interactive requires a terminal stdin")
		}
		if _, err := fmt.Fprint(stderr, "Enter password: "); err != nil {
			return "", err
		}
		password, err := term.ReadPassword(int(terminal.Fd()))
		if _, writeErr := fmt.Fprintln(stderr); writeErr != nil && err == nil {
			err = writeErr
		}
		if err != nil {
			return "", fmt.Errorf("read interactive password: %w", err)
		}
		if len(password) == 0 {
			return "", errors.New("interactive password must not be empty")
		}
		if !utf8.Valid(password) {
			return "", errors.New("interactive password must be valid UTF-8")
		}
		if len(password) > maxInputBytes {
			return "", fmt.Errorf("interactive password exceeds %d bytes", maxInputBytes)
		}
		return string(password), nil
	}
	if cfg.words > 0 {
		return generateWords(words, cfg.words, cfg.separator, cfg.prefix, cfg.suffix, randomReader)
	}
	length := cfg.length
	if cfg.bits > 0 {
		var err error
		length, err = lengthForBits(cfg.bits, len(alphabet))
		if err != nil {
			return "", err
		}
	}
	return generateCharacters(alphabet, length, cfg.groupSize, cfg.groupSeparator, cfg.prefix, cfg.suffix, randomReader)
}

func lengthForBits(bits, alphabetSize int) (int, error) {
	if alphabetSize < 2 {
		return 0, errors.New("--bits requires an alphabet with at least two characters")
	}
	length := int(math.Ceil(float64(bits) / math.Log2(float64(alphabetSize))))
	if length < 1 || length > maxRandomLength {
		return 0, fmt.Errorf("--bits requires more than %d random characters", maxRandomLength)
	}
	return length, nil
}

func generateCharacters(alphabet string, length, groupSize int, groupSeparator, prefix, suffix string, randomReader io.Reader) (string, error) {
	randomComponent, err := randomString(alphabet, length, randomReader)
	if err != nil {
		return "", err
	}
	if groupSize > 0 {
		groups := make([]string, 0, (len(randomComponent)+groupSize-1)/groupSize)
		for start := 0; start < len(randomComponent); start += groupSize {
			end := start + groupSize
			if end > len(randomComponent) {
				end = len(randomComponent)
			}
			groups = append(groups, randomComponent[start:end])
		}
		randomComponent = strings.Join(groups, groupSeparator)
	}
	return prefix + randomComponent + suffix, nil
}

func randomString(alphabet string, length int, randomReader io.Reader) (string, error) {
	result := make([]byte, length)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range result {
		index, err := rand.Int(randomReader, limit)
		if err != nil {
			return "", fmt.Errorf("sample random character: %w", err)
		}
		result[i] = alphabet[index.Int64()]
	}
	return string(result), nil
}

func generateWords(words []string, count int, separator, prefix, suffix string, randomReader io.Reader) (string, error) {
	selected := make([]string, count)
	limit := big.NewInt(int64(len(words)))
	for i := range selected {
		index, err := rand.Int(randomReader, limit)
		if err != nil {
			return "", fmt.Errorf("sample random word: %w", err)
		}
		selected[i] = words[index.Int64()]
	}
	return prefix + strings.Join(selected, separator) + suffix, nil
}

func deriveResult(plaintext, name string, iterations int, emit emitFields, randomReader io.Reader) (outputResult, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(randomReader, salt); err != nil {
		return outputResult{}, fmt.Errorf("generate SCRAM salt: %w", err)
	}
	scram, err := scramVerifier(plaintext, salt, iterations)
	if err != nil {
		return outputResult{}, err
	}
	shaSum := sha256.Sum256([]byte(plaintext))

	result := outputResult{}
	if emit.plaintext {
		result.Plaintext = new(plaintext)
	}
	if emit.sha256 {
		result.SHA256 = new(hex.EncodeToString(shaSum[:]))
	}
	if emit.scram {
		result.SCRAMSHA256 = new(scram)
	}
	if emit.name {
		result.Name = new(name)
	}
	return result, nil
}

func scramVerifier(plaintext string, salt []byte, iterations int) (string, error) {
	saltedPassword, err := pbkdf2.Key(sha256.New, plaintext, salt, iterations, digestLen)
	if err != nil {
		return "", fmt.Errorf("derive SCRAM password: %w", err)
	}
	clientKey := hmacSHA256(saltedPassword, clientRawKey)
	storedKeySum := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(saltedPassword, serverRawKey)
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(storedKeySum[:]),
		base64.StdEncoding.EncodeToString(serverKey)), nil
}

func hmacSHA256(key, message []byte) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write(message)
	return hash.Sum(nil)
}

func encodeResults(format string, yamlIndent int, results []outputResult, stdout io.Writer) error {
	switch format {
	case "yaml":
		encoder := yaml.NewEncoder(stdout)
		encoder.SetIndent(yamlIndent)
		encoder.CompactSeqIndent()
		if err := encoder.Encode(results); err != nil {
			return fmt.Errorf("encode YAML: %w", err)
		}
		if err := encoder.Close(); err != nil {
			return fmt.Errorf("close YAML encoder: %w", err)
		}
		return nil
	case "json":
		encoder := json.NewEncoder(stdout)
		if len(results) == 1 {
			return encoder.Encode(results[0])
		}
		return encoder.Encode(results)
	case "plain":
		for _, result := range results {
			if _, err := fmt.Fprintln(stdout, *result.Plaintext); err != nil {
				return err
			}
		}
		return nil
	case "scram":
		for _, result := range results {
			if _, err := fmt.Fprintln(stdout, *result.SCRAMSHA256); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported --format %q", format)
	}
}
