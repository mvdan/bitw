// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"encoding/json"
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
		"bitw": func() int {
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
		"2fa": func() int {
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
	if err != nil {
		t.Fatal(err)
	}

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

// These values correspond to a dummy test account where some dummy data was
// stored to obtain cipher strings. Nothing with the account was ever actually
// secret or protected, because we don't need to log into the account to run the
// tests (unlike the end-to-end tests).
const (
	localTestPassword = "PasswordForTestData"
	localTestProfile  = `
{
	"Email": "testdata@mvdan.cc",
	"Key": "2.i30jRRMW+S48hHH8ASkQyA==|rOCrwgiSkmjRP33d6rSmkc0KQ14AVZji6gL2GhLFt4ZWA0RuleONpMF+Bt8tr0ulLT0qhtpDbyJjs8UVQiL57OBIfB/s85Bw4vRXYJWvYQE=|HCXNwbnNXQYPQ4hz3DmALn21tUGqd9wjnEzJDwSp8YA=",
	"PrivateKey": "2.VUp/AjLpJpHiuZbZQflzIw==|vBOmZQoRhOxzHFIdZmWNmiuajzsyRV4PE0Bw2eFeSea9jB06obRFPtj3NSWpyKOAArY9PgiTU054RGvVJZEp1mBp+NA7zVSyTYA2yDymmW73yrdeH0Rn0nVUcjkscVJqvpPAq4SBv7Lcb/46YZwAcuDDCCYI+VxDqVGaj33hbd7g7VRSKKhT3U6SvohY2dthwXwb3svQ5xCTaip7PlvJxeF4PLNKCDtYUws6VB0D7Fct0M68lhyF9H3fDY8r8dCJ40r/wUZw7Go+t458D4hLbgvwQomdaUB6HtSUo6Gdygs44hsaR7CKpCkpxWnu4rdqRTw9xrFziPDH4gGKmm3f77qZRDJIYqkXhjRLJIXY03Ceug6AEBYWmfvEDrvI7xhaYzS7gMJIBVbWHtT5/tN9klS3DUaLnyHLfB2+j1vRWANid+O/+K0E0BNCTg9gpZwYd7qcPFvxkKaCYJZ5LUjbzDdunxK8scIqUAobmnoHLsGcxNlDwRRebIm9fabQuUQWFOQGzvZnD2dsbG0zPath8lD/K4S22emrCj+ZBFCTyMQd7E9qOvLdJ2s4NDh2shgPYHgHh34R5LEyVUR8Vot6Pd7DFZGF4D6zW4w5hsfhtcyU4ljs60NdSR7XQO2/AD5R2bg/k8yXV452L96bonFYKbUI4n/68/MGwe+8Q5aNcHHp6Eo0Yg9K79mK/kYlZOfk7m4uotQjg378j8bMXGoNy9grbjypH+MaDKKp7woSxjJI/IWOp9UWrEUWplAOKgcms5j0NVfZQCdYAW4SvQLS2hGKZ05zyaNgY1vNIAQG6uKb3Bt3CVN/Pl8G99s/qcRgl+cwRz4TlBXKkEE6jinBFF07H2BzBcAlOFOzZoUfzkWIhZvTtUgsC7PEe1+SvdtnZ7Gh8mRoZ9XbUV/RHmXE/dRDBGmxteaIsUc+cI17ykB7wl51aLjoPR4Qxvr8giEsEgWwI2SCW/Nn9PYvEhQLiqk/GM9xH9ChUUq5rWVCI3phuP9uTQOSYCihi2Te1HWxbwPMsIH2kBWtrvM8hNbP8bTMw+rfCa/6Dujx8Nq1pTEg9PrXsXw7KhQrNOMSIuDFvWJUUJC06dxYz4F7Rv2AbRLvFlawFm2l7fRp85E/Rssij+iqj++8XZSl2GQFZbWD4sj23JvpSQdvbZ9kamTvuuohYuCg9qfugWx3Wr9BhGT+E9i0cr01EtGaCwslN65kvtUaB3GrOwEOk3/i83ES223Z+TKWrLKbwVChUBtxCgkVBTLRto37obDjJMb2Z+pVla6wPCBObmqpW7k+TGVIGNCt+TFWA7jh2cs4Shid5qMpnWzShZBtgBAvoPZ1t2IbZVYPHL4V/kRvwax3stHziG5CDiYJD7HAP8SqazBE4ZJMoTuVOjh+GuV15SpL+N4+UlvmX+PKPFVqB0jbF1HH9/Wbw8XZxBsNGp+nz15X91zV4+2i5PapTHsDiq2XH68e3bS2esFbCmGoGqM4JrSQP8w9mMpnwj1gQXpmRitL0L3cU6oHGpe4Hpmf7/zckhS0cUaRTk0bTnFF8ILgd/LBGOb7UBu+VpjSOftiJkTWUG/8/jjoF8KfbBblnGWjmLiPR19Eb4+Q2yDtCZlm35sBnmJy0lsv/XZ7geTLtqjyu8s=|2JpLpBL8HPr6aLHVG9+zs0YsL5TEPBo1VM+Ccmzv30g="
}`
)

var cipherStringTests = []struct {
	name  string
	input string
	want  string
}{
	{
		"Empty",
		"",
		"",
	},
	{
		"AesCbc256_HmacSha256_B64",
		"2.UOwWp1xffLz5x3nfNakP2A==|3CxjtqZA378Vjt/9CSYT6Q==|YNGr+MlARtB2k27ojyNOgXKCUwVQu/y0ZbXaI7FEcsA=",
		"some name",
	},
}

// TestCipherString helps us cover the various kinds of cipher strings via unit
// tests, since it would be pretty difficult to cover all the edge cases with
// full end-to-end tests. Normally, a real Bitwarden account will use a
// recent/modern cipher string type for all of its encrypted data.
func TestCipherString(t *testing.T) {
	t.Parallel()
	secrets := secretCache{
		_password: []byte(localTestPassword),
		data:      &dataFile{KDFIterations: 100000},
	}
	err := json.Unmarshal([]byte(localTestProfile), &secrets.data.Sync.Profile)
	qt.Assert(t, err, qt.IsNil)

	for _, test := range cipherStringTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Note that secretCache is not safe for concurrent use,
			// for now.
			// t.Parallel()

			var cipher CipherString
			err := cipher.UnmarshalText([]byte(test.input))
			qt.Assert(t, err, qt.IsNil)

			got, err := secrets.decryptStr(cipher)
			qt.Assert(t, err, qt.IsNil)

			qt.Assert(t, string(got), qt.Equals, test.want)
		})
	}
}
