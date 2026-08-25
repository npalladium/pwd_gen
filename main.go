// Generates passwords and their "hashed" formats (SHA-256 and SCRAM-SHA-256)
// SHA256 is a common hashing mechanism for passwords.
// SCRAM-SHA-256 is used by postgres.

package main

// @see https://github.com/postgres/postgres/blob/c30f54ad732ca5c8762bb68bbe0f51de9137dd72/src/interfaces/libpq/fe-auth.c#L1167-L1285
// @see https://github.com/postgres/postgres/blob/e6bdfd9700ebfc7df811c97c2fc46d7e94e329a2/src/interfaces/libpq/fe-auth-scram.c#L868-L905
// @see https://github.com/postgres/postgres/blob/c30f54ad732ca5c8762bb68bbe0f51de9137dd72/src/port/pg_strong_random.c#L66-L96
// @see https://github.com/postgres/postgres/blob/e6bdfd9700ebfc7df811c97c2fc46d7e94e329a2/src/common/scram-common.c#L160-L274
// @see https://github.com/postgres/postgres/blob/e6bdfd9700ebfc7df811c97c2fc46d7e94e329a2/src/common/scram-common.c#L27-L85

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v3"
)

const (
	// @see https://github.com/postgres/postgres/blob/e6bdfd9700ebfc7df811c97c2fc46d7e94e329a2/src/include/common/scram-common.h#L36-L41
	saltSize = 16

	// @see https://github.com/postgres/postgres/blob/c30f54ad732ca5c8762bb68bbe0f51de9137dd72/src/include/common/sha2.h#L22
	digestLen = 32

	// @see https://github.com/postgres/postgres/blob/e6bdfd9700ebfc7df811c97c2fc46d7e94e329a2/src/include/common/scram-common.h#L43-L47
	iterationCnt = 4096
)

var (
	clientRawKey = []byte("Client Key")
	serverRawKey = []byte("Server Key")
)

func genSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func encodeB64(src []byte) (dst []byte) {
	dst = make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return
}

func getHMACSum(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func getSHA256Sum(key []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(key)
	return h.Sum(nil)
}

func encryptPassword(rawPassword, salt []byte, iter, keyLen int) string {
	digestKey := pbkdf2.Key(rawPassword, salt, iter, keyLen, sha256.New)
	clientKey := getHMACSum(digestKey, clientRawKey)
	storedKey := getSHA256Sum(clientKey)
	serverKey := getHMACSum(digestKey, serverRawKey)

	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iter,
		string(encodeB64(salt)),
		string(encodeB64(storedKey)),
		string(encodeB64(serverKey)),
	)
}

func generatePassword(length int) ([]byte, error) {
	const (
		// remove confusing chars: iIlL1, oO0, sS5
		lowerCharSet   = "abcdedfghjkmnpqrt"
		upperCharSet   = "ABCDEFGHJKMNPQRTUVWXYZ"
		specialCharSet = "" // "!@#$%&*"
		numberSet      = "2346789"
		allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
	)
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(allCharSet))))
		if err != nil {
			return []byte{}, err
		}
		ret[i] = allCharSet[num.Int64()]
	}
	return ret, nil
}

type options struct {
	ReadPasswordInteractively bool
	PasswordLength            int
	OutputFormat              string
	Name                      string
}

func getPassword(args []string, flags options) ([]byte, error) {
	if len(args) == 1 {
		return []byte(args[0]), nil
	} else if flags.ReadPasswordInteractively {
		fmt.Print("Enter password: ")
		return terminal.ReadPassword(syscall.Stdin)
	} else {
		return generatePassword(32)
	}
}
func run(args []string, flags options) (err error) {
	rawPassword, err := getPassword(args, flags)
	if err != nil {
		return err
	}
	salt, err := genSalt(saltSize)
	if err != nil {
		return err
	}

	d, err := yaml.Marshal([]struct{ Plaintext, SHA_256, SCRAM_SHA_256, Name string }{
		{
			Plaintext:     string(rawPassword),
			SHA_256:       fmt.Sprintf("%x", getSHA256Sum(rawPassword)),
			SCRAM_SHA_256: fmt.Sprintf("%s", encryptPassword(rawPassword, salt, iterationCnt, digestLen)),
			Name:          flags.Name,
		},
	})
	fmt.Println(string(d))
	return
}

func main() {
	flags := options{}
	flag.IntVar(&flags.PasswordLength, "length", 32, "length of password")
	flag.BoolVar(&flags.ReadPasswordInteractively, "interactive", false, "take password input")
	flag.StringVar(&flags.OutputFormat, "format", "yaml", "output format")
	flag.StringVar(&flags.Name, "name", "", "friendly name of password")
	flag.Parse()
	args := flag.Args()
	err := run(args, flags)
	if err != nil {
		log.Fatal(err)
	}
}
