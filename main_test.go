// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"bitw": main1,
		"waitfile": func() int {
		Files:
			for _, path := range os.Args[1:] {
				fmt.Println(path[1:])
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
	}))
}

var write = flag.Bool("w", false, "update saved testdata files")

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
			if err := os.MkdirAll(cfgDir, 0755); err != nil {
				return err
			}

			env.Vars = append(env.Vars, "TESTDATA="+testdata)

			// Secrets should pass through.
			for _, name := range [...]string{
				"PASSWORD_NOTFA",
			} {
				env.Vars = append(env.Vars, name+"="+os.Getenv(name))
			}

			path := filepath.Join(cfgDir, "data.json")
			if err := ioutil.WriteFile(path, baseData, 0600); err != nil {
				return err
			}

			path = filepath.Join(cfgDir, "data-notfa.json")
			if err := ioutil.WriteFile(path, savedData, 0600); err != nil {
				return err
			}
			return nil
		},
		Condition: func(cond string) (bool, error) {
			if strings.HasPrefix(cond, "env:") {
				return os.Getenv(cond[4:]) != "", nil
			}
			switch cond {
			case "write":
				return *write, nil
			}
			return false, nil
		},
	})
}

// baseData is set up for all tests, so that the test emails don't get "new
// device logged in" every time the tests run.
var baseData = []byte(`
{
	"DeviceID": "cfd6811f-7f66-4393-bbdf-4d509ae4904b"
}
`)[1:]
