// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/kenshaw/ini"
	"golang.org/x/term"
)

var flagSet = flag.NewFlagSet("bitw", flag.ContinueOnError)

func init() { flagSet.Usage = usage }

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage of bitw:

	bitw [command]

Commands:

	help    show a command's help text
	sync    fetch the latest data from the server
	login   force a new login, even if not necessary
	dump    list all the stored login secrets
	serve   start the org.freedesktop.secrets D-Bus service
	config  print the current configuration
`[1:])
	flagSet.PrintDefaults()
}

func main() { os.Exit(main1(os.Stderr)) }

func main1(stderr io.Writer) int {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return 2
	}
	args := flagSet.Args()
	if err := run(args...); err != nil {
		switch err {
		case context.Canceled:
			return 0
		case flag.ErrHelp:
			return 2
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// These can be overriden by the config.
var (
	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"
)

// readLine is similar to term.ReadPassword, but it doesn't use key codes.
func readLine(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	defer fmt.Fprintln(os.Stderr)

	var buf [1]byte
	var line []byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				return line, nil
			default:
				line = append(line, buf[0])
			}
		} else if err != nil {
			if err == io.EOF && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

func passwordPrompt(prompt string) ([]byte, error) {
	// TODO: Support cancellation with ^C. Currently not possible in any
	// simple way. Closing os.Stdin on cancel doesn't seem to do the trick
	// either. Simply doing an os.Exit keeps the terminal broken because of
	// ReadPassword.

	fd := int(os.Stdin.Fd())
	switch {
	case term.IsTerminal(fd):
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err == nil && len(password) == 0 {
			err = io.ErrUnexpectedEOF
		}
		return password, err
	case os.Getenv("FORCE_STDIN_PROMPTS") == "true":
		return readLine(prompt)
	default:
		return nil, fmt.Errorf("need a terminal to prompt for a password")
	}
}

var (
	config     *ini.File
	globalData dataFile

	saveData bool

	secrets secretCache
)

func init() { secrets.data = &globalData }

type dataFile struct {
	path string

	DeviceID      string
	AccessToken   string
	RefreshToken  string
	TokenExpiry   time.Time
	KDF           int
	KDFIterations int

	LastSync time.Time
	Sync     SyncData
}

func loadDataFile(path string) error {
	globalData.path = path
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&globalData); err != nil {
		return err
	}
	return nil
}

func (f *dataFile) Save() error {
	bs, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	bs = append(bs, '\n')
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	return ioutil.WriteFile(f.path, bs, 0o600)
}

func run(args ...string) (err error) {
	if len(args) == 0 {
		flagSet.Usage()
		return flag.ErrHelp
	}
	switch args[0] {
	case "help":
		// TODO: per-command help
		flagSet.Usage()
		return flag.ErrHelp
	}
	dir := os.Getenv("CONFIG_DIR")
	if dir == "" {
		if dir, err = os.UserConfigDir(); err != nil {
			return err
		}
		dir = filepath.Join(dir, "bitw")
	}
	config, err = ini.LoadFile(filepath.Join(dir, "config"))
	if err != nil {
		return err
	}
	for _, section := range config.AllSections() {
		if section.Name() != "" {
			return fmt.Errorf("sections are not used in config files yet")
		}
		for _, key := range section.Keys() {
			// note that these are lowercased
			switch key {
			case "email":
				secrets._configEmail = section.Get(key)
			case "apiurl":
				apiURL = section.Get(key)
			case "identityurl":
				idtURL = section.Get(key)
			default:
				return fmt.Errorf("unknown config key: %q", key)
			}
		}
	}

	dataPath := filepath.Join(dir, "data.json")
	if err := loadDataFile(dataPath); err != nil {
		return fmt.Errorf("could not load %s: %v", dataPath, err)
	}

	if args[0] == "config" {
		fmt.Printf("email       = %q\n", secrets.email())
		fmt.Printf("apiURL      = %q\n", apiURL)
		fmt.Printf("identityURL = %q\n", idtURL)
		return nil
	}

	defer func() {
		if !saveData {
			return
		}
		if err1 := globalData.Save(); err == nil {
			err = err1
		}
	}()

	if globalData.DeviceID == "" {
		globalData.DeviceID = uuid.New().String()
		saveData = true
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cancel()
	}()

	ctx = context.WithValue(ctx, authToken{}, globalData.AccessToken)
	switch args[0] {
	case "login":
		if err := login(ctx); err != nil {
			return err
		}
	case "sync":
		if err := ensureToken(ctx); err != nil {
			return err
		}
		if err := sync(ctx); err != nil {
			return err
		}
	case "dump":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
		fmt.Fprintln(w, "name\turi\tusername\tpassword\t")
		for _, cipher := range globalData.Sync.Ciphers {
			for _, cipherStr := range [...]CipherString{
				cipher.Name,
				cipher.Login.URI,
				cipher.Login.Username,
				cipher.Login.Password,
			} {
				s, err := secrets.decrypt(cipherStr)
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "%s\t", s)
			}
			fmt.Fprintln(w)
		}
		w.Flush()
	case "serve":
		if err := serveDBus(ctx); err != nil {
			return err
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		flagSet.Usage()
		return flag.ErrHelp
	}
	return nil
}

func ensureToken(ctx context.Context) error {
	if globalData.RefreshToken == "" {
		if err := login(ctx); err != nil {
			return err
		}
	} else if time.Now().After(globalData.TokenExpiry) {
		if err := refreshToken(ctx); err != nil {
			return err
		}
	}
	return nil
}
