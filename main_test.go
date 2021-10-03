// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/rogpeppe/go-internal/testscript"
)

type bitwMain struct {
	m *testing.M
}

func (m bitwMain) Run() int {
	// Don't let the parent environment mess with our tests.
	os.Unsetenv("EMAIL")
	os.Unsetenv("PASSWORD")
	return m.m.Run()
}

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(bitwMain{m}, map[string]func() int{
		"bitw": func() int { return main1(os.Stderr) },
		// bitw-toomany is a helpful command to use in some of the
		// scripts talking to bitwarden.com. In particular, it reports
		// "too many requests" via a file.
		"bitw-toomany": func() int {
			stderr := new(bytes.Buffer)
			code := main1(stderr)
			s := stderr.String()
			fmt.Fprint(os.Stderr, s)
			// If we get a 429, succeed and write a special empty
			// file, so that the test can be skipped.
			if strings.Contains(s, "Too Many Requests:") {
				if err := ioutil.WriteFile("toomany", nil, 0o600); err != nil {
					fmt.Println(err)
				}
				return 0
			}
			return code
		},
		"waitfile": func() int {
		Files:
			for _, path := range os.Args[1:] {
				for i := 0; i < 10; i++ {
					if _, err := os.Lstat(path); err == nil {
						continue Files
					} else {
						fmt.Println(err)
					}
					time.Sleep(10 * time.Millisecond)
				}
				fmt.Printf("timed out waiting for %q\n", path)
				return 1
			}
			return 0
		},
		"waitexec": func() int {
			for i := 0; i < 10; i++ {
				cmd := exec.Command(os.Args[1], os.Args[2:]...)
				if out, err := cmd.CombinedOutput(); err == nil {
					return 0
				} else {
					fmt.Println(string(out))
					fmt.Println(err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			fmt.Printf("timed out waiting for %q\n", os.Args[1:])
			return 1
		},
		"2fa-wrap": func() int {
			key := os.Args[1]
			dst := os.Args[2]
			// TODO: don't require rsc.io/2fa
			cmd := exec.Command("2fa", "-add", "tmp")
			cmd.Stdin = strings.NewReader(key + "\n")
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Println(string(out))
				fmt.Println(err)
				return 1
			}
			cmd = exec.Command("2fa", "-clip", "tmp")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(string(out))
				fmt.Println(err)
				return 1
			}
			// Select the first 2fa method, "authenticator".
			out = append([]byte("1\n"), out...)
			if err := ioutil.WriteFile(dst, out, 0o600); err != nil {
				fmt.Println(err)
				return 1
			}
			return 0
		},
	}))
}

var (
	write  = flag.Bool("w", false, "update saved testdata files")
	update = flag.Bool("u", false, "update testscript output files")
)

func TestScripts(t *testing.T) {
	t.Parallel()

	testdata, err := filepath.Abs("testdata")
	qt.Assert(t, err, qt.IsNil)

	// Don't stop on an error, to let a test write to the path. The test
	// needing the file can skip itself.
	savedData, _ := ioutil.ReadFile(filepath.Join(testdata, "data-notfa.json"))

	testscript.Run(t, testscript.Params{
		Dir: filepath.Join("testdata", "scripts"),
		Setup: func(env *testscript.Env) error {
			home := filepath.Join(env.WorkDir, "home")
			env.Vars = append(env.Vars, "HOME="+home)

			cfgDir := filepath.Join(home, "config")
			env.Vars = append(env.Vars, "CONFIG_DIR="+cfgDir)
			if err := os.MkdirAll(cfgDir, 0o755); err != nil {
				return err
			}

			env.Vars = append(env.Vars, "TESTDATA="+testdata)

			// Secrets should pass through.
			for _, name := range [...]string{
				"PASSWORD_NOTFA",
				"PASSWORD_WITHTFA",
				"TFAKEY",
			} {
				env.Vars = append(env.Vars, name+"="+os.Getenv(name))
			}

			path := filepath.Join(cfgDir, "data.json")
			if err := ioutil.WriteFile(path, baseData, 0o600); err != nil {
				return err
			}

			path = filepath.Join(cfgDir, "data-notfa.json")
			if err := ioutil.WriteFile(path, savedData, 0o600); err != nil {
				return err
			}
			return nil
		},
		Condition: func(cond string) (bool, error) {
			if strings.HasPrefix(cond, "env:") {
				return os.Getenv(cond[4:]) != "", nil
			}
			if strings.HasPrefix(cond, "file:") {
				_, err := os.Lstat(cond[5:])
				return err == nil, nil
			}
			switch cond {
			case "write":
				return *write, nil
			}
			return false, nil
		},
		UpdateScripts: *update,
	})
}

// baseData is set up for all tests, so that the test emails don't get "new
// device logged in" every time the tests run.
var baseData = []byte(`
{
	"DeviceID": "cfd6811f-7f66-4393-bbdf-4d509ae4904b"
}
`)[1:]

// These values initially corresponded to a dummy test account where some dummy
// data was stored to obtain cipher strings. Nothing with the account was ever
// actually secret or protected, because we don't need to log into the account
// to run the tests (unlike the end-to-end tests).
const (
	localTestPassword = "PasswordForTestData"
	localTestEmail    = "testdata@mvdan.cc"

	// A 32-byte key encrypted with AesCbc256_B64.
	localTestKey0 = "0.tgrxn4Ve2pPL0M+6/B2e/g==|xfq496HVhDHeoJCKWfXBg/6+cE94KfM0AzV3IJUoWlkqoPR2heODBSQnQ8ZACzHE"

	// A 64-byte key encrypted with AesCbc256_HmacSha256_B64.
	localTestKey2 = "2.i30jRRMW+S48hHH8ASkQyA==|rOCrwgiSkmjRP33d6rSmkc0KQ14AVZji6gL2GhLFt4ZWA0RuleONpMF+Bt8tr0ulLT0qhtpDbyJjs8UVQiL57OBIfB/s85Bw4vRXYJWvYQE=|HCXNwbnNXQYPQ4hz3DmALn21tUGqd9wjnEzJDwSp8YA="
)

var cipherStringTests = []struct {
	name     string
	inKey    string
	inCipher string
	want     string
}{
	{
		"Empty",
		"",
		"",
		"",
	},
	{
		"AesCbc256_HmacSha256_B64/SameKey",
		localTestKey2,
		"2.UOwWp1xffLz5x3nfNakP2A==|3CxjtqZA378Vjt/9CSYT6Q==|YNGr+MlARtB2k27ojyNOgXKCUwVQu/y0ZbXaI7FEcsA=",
		"some name",
	},
	{
		"AesCbc256_HmacSha256_B64/SpecialPadding",
		localTestKey2,
		"2.K20OZwt1w/U9JiIXT++P6w==|QAIl3SyEMFML9/xgUiRqQPIskKKNJiMwVT125+Z0ETw=|6qFHN8QgdWFLmMTB4ZnjB+zKvFm67HRZcA5a5b9o6lY=",
		"exactly sixteen!",
	},
	{
		"AesCbc256_B64/SameKey",
		localTestKey0,
		"0.gAkDPu4VBwz+k/cYWnpSJQ==|3hLXTjkEStWVvSuBWB4AJw==",
		"some name",
	},
}

// TestCipherString helps us cover the various kinds of cipher strings via unit
// tests, since it would be pretty difficult to cover all the edge cases with
// full end-to-end tests. Normally, a real Bitwarden account will use a
// recent/modern cipher string type for all of its encrypted data.
func TestCipherString(t *testing.T) {
	t.Parallel()
	for _, test := range cipherStringTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Set up secretCache, decoding the key cipher string too.
			secrets := secretCache{
				_password: []byte(localTestPassword),
				data:      &dataFile{KDFIterations: 100000},
			}
			secrets.data.Sync.Profile.Email = localTestEmail
			err := secrets.data.Sync.Profile.Key.UnmarshalText([]byte(test.inKey))
			qt.Check(t, err, qt.IsNil)

			// Decode the cipher string.
			var inputCipher CipherString
			err = inputCipher.UnmarshalText([]byte(test.inCipher))
			qt.Check(t, err, qt.IsNil)

			// Decrypt it, and ensure we get the same plaintext.
			gotPlain, err := secrets.decrypt(inputCipher)
			qt.Check(t, err, qt.IsNil)
			qt.Check(t, string(gotPlain), qt.Equals, test.want)

			// Encrypt it, and check that we get the same length.
			gotCipher, err := secrets.encryptType([]byte(test.want), inputCipher.Type)
			qt.Check(t, err, qt.IsNil)
			qt.Check(t, gotCipher.String(), qt.HasLen, len(test.inCipher))

			// Decrypt the cipher string we encrypted, to check that
			// we still get the same plaintext. This ensures the
			// full roundtrip works.
			gotPlain, err = secrets.decrypt(gotCipher)
			qt.Check(t, err, qt.IsNil)
			qt.Check(t, string(gotPlain), qt.Equals, test.want)
		})
	}
}
