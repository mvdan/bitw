// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/kenshaw/ini"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
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

const (
	deviceName = "firefox"
	deviceType = "3" // bitwarden's device type for FireFox
	loginScope = "api offline_access"
)

// These can be overriden by the config.
var (
	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"

	email = os.Getenv("EMAIL")

	// TODO: make these more secure
	password    []byte
	key, macKey []byte
)

func ensurePassword() error {
	if len(password) > 0 {
		return nil
	}
	if s := os.Getenv("PASSWORD"); s != "" {
		password = []byte(s)
		return nil
	}
	var err error
	password, err = passwordPrompt("Password")
	return err
}

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
	config *ini.File
	data   dataFile

	saveData bool
)

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
	data.path = path
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&data); err != nil {
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
				email = section.Get(key)
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
		fmt.Printf("email       = %q\n", email)
		fmt.Printf("apiURL      = %q\n", apiURL)
		fmt.Printf("identityURL = %q\n", idtURL)
		return nil
	}

	defer func() {
		if !saveData {
			return
		}
		if err1 := data.Save(); err == nil {
			err = err1
		}
	}()

	if data.DeviceID == "" {
		data.DeviceID = uuid.New().String()
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

	ctx = context.WithValue(ctx, authToken{}, data.AccessToken)
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
		for _, cipher := range data.Sync.Ciphers {
			for _, cipherStr := range [...]CipherString{
				cipher.Name,
				cipher.Login.URI,
				cipher.Login.Username,
				cipher.Login.Password,
			} {
				s, err := decrypt(cipherStr)
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
	if data.RefreshToken == "" {
		if err := login(ctx); err != nil {
			return err
		}
	} else if time.Now().After(data.TokenExpiry) {
		if err := refreshToken(ctx); err != nil {
			return err
		}
	}
	return nil
}

func ensureDecryptKey() error {
	if len(key) > 0 {
		return nil
	}
	if email == "" {
		// If the user specified $EMAIL just for the login, grab it from
		// the data file now.
		email = data.Sync.Profile.Email
	}
	if err := ensurePassword(); err != nil {
		return err
	}
	masterKey := pbkdf2.Key(password, []byte(strings.ToLower(email)),
		data.KDFIterations, 32, sha256.New)

	// We decrypt the decryption key from the synced data, using the key
	// resulting from stretching masterKey. The keys will be overwritten
	// once we decrypt the final ones.
	key, macKey = stretchKey(masterKey)

	s, err := decrypt(data.Sync.Profile.Key)
	if err != nil {
		return err
	}
	key, macKey = s[:32], s[32:64]
	return nil
}

func stretchKey(orig []byte) (key, macKey []byte) {
	key = make([]byte, 32)
	macKey = make([]byte, 32)
	var r io.Reader
	r = hkdf.Expand(sha256.New, orig, []byte("enc"))
	r.Read(key)
	r = hkdf.Expand(sha256.New, orig, []byte("mac"))
	r.Read(macKey)
	return key, macKey
}

func decryptStr(s CipherString) (string, error) {
	dec, err := decrypt(s)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// TODO: turn this into a method

func decrypt(s CipherString) ([]byte, error) {
	if s.Type == 0 {
		return nil, nil
	}
	if err := ensureDecryptKey(); err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.Type {
	case 2:
		// AES-CBC-256, HMAC-SHA256, base-64; continues below
	default:
		return nil, fmt.Errorf("unsupported cipher type %q", s.Type)
	}

	if macKey != nil {
		var msg []byte
		msg = append(msg, s.IV...)
		msg = append(msg, s.CT...)
		if !validMAC(msg, s.MAC, macKey) {
			return nil, fmt.Errorf("MAC mismatch")
		}
	}

	decrypter := cipher.NewCBCDecrypter(c, s.IV)
	dst := make([]byte, len(s.CT))
	decrypter.CryptBlocks(dst, s.CT)
	dst = unpad(dst)
	return dst, nil
}

func unpad(src []byte) []byte {
	n := src[len(src)-1]
	return src[:len(src)-int(n)]
}

func validMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
