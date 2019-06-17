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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/knq/ini"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
)

var flagSet = flag.NewFlagSet("bitw", flag.ContinueOnError)

func init() { flagSet.Usage = usage }

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage of bitw:

	benchinit [flags] [command]

Commands:

	sync    fetch the latest data from the server
`[1:])
	flagSet.PrintDefaults()
}

func main() { os.Exit(main1()) }

func main1() int {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		if err != flag.ErrHelp {
			fmt.Fprintf(os.Stderr, "flag: %v\n", err)
			flagSet.Usage()
		}
		return 2
	}
	args := flagSet.Args()
	if len(args) == 0 {
		flagSet.Usage()
		return 2
	}
	if err := run(args...); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
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

	email    = os.Getenv("EMAIL")
	password []byte // TODO: make this more secure
)

func ensurePassword() error {
	if len(password) > 0 {
		return nil
	}
	if s := os.Getenv("PASSWORD"); s != "" {
		password = []byte(s)
		return nil
	}
	fd := int(os.Stdin.Fd())
	if !terminal.IsTerminal(fd) {
		return fmt.Errorf("non-interactive mode needs $PASSWORD")
	}
	var err error
	password, err = terminal.ReadPassword(fd)
	return err
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
	if err := os.MkdirAll(filepath.Dir(f.path), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(f.path, bs, 0600)
}

func run(args ...string) (err error) {
	dir, err := userConfigDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, "bitw")
	config, err = ini.LoadFile(filepath.Join(dir, "config"))
	if err != nil {
		return err
	}
	if err := loadDataFile(filepath.Join(dir, "data.json")); err != nil {
		return err
	}
	defer func() {
		if !saveData {
			return
		}
		if err1 := data.Save(); err == nil {
			err = err1
		}
	}()

	if e := config.GetKey("email"); e != "" {
		email = e
	}
	if u := config.GetKey("apiURL"); u != "" {
		apiURL = u
	}
	if u := config.GetKey("identityURL"); u != "" {
		idtURL = u
	}

	if data.DeviceID == "" {
		data.DeviceID = uuid.New().String()
		saveData = true
	}

	ctx := context.Background()

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
		key, macKey, err := decryptKey()
		if err != nil {
			return err
		}
		for _, cipher := range data.Sync.Ciphers {
			name, err := decrypt(key, macKey, cipher.Name)
			if err != nil {
				return err
			}
			uri, err := decrypt(key, macKey, cipher.Login.URI)
			if err != nil {
				return err
			}
			pw, err := decrypt(key, macKey, cipher.Login.Password)
			if err != nil {
				return err
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", cipher.ID, name, uri, pw)
		}
	default:
		flagSet.Usage()
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

func decryptKey() (key, macKey []byte, err error) {
	if err := ensurePassword(); err != nil {
		return nil, nil, err
	}
	masterKey := pbkdf2.Key(password, []byte(strings.ToLower(email)),
		data.KDFIterations, 32, sha256.New)
	encKey0, macKey0 := stretchKey(masterKey)
	s, err := decrypt(encKey0, macKey0, data.Sync.Profile.Key)
	if err != nil {
		return nil, nil, err
	}
	key, macKey = s[:32], s[32:64]
	return key, macKey, nil
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

func decrypt(key, macKey []byte, cipherStr string) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	typ, iv, ct, mac, err := parseCipher(cipherStr)
	if err != nil {
		return nil, err
	}
	switch typ {
	case 2:
		// AES-CBC-256, HMAC-SHA256, base-64; continues below
	default:
		return nil, fmt.Errorf("unsupported cipher type %q", typ)
	}

	if macKey != nil {
		var msg []byte
		msg = append(msg, iv...)
		msg = append(msg, ct...)
		if !validMAC(msg, mac, macKey) {
			return nil, fmt.Errorf("MAC mismatch")
		}
	}

	decrypter := cipher.NewCBCDecrypter(c, iv)
	decrypter.CryptBlocks(ct, ct)
	ct = unpad(ct)
	return ct, nil
}

func unpad(src []byte) []byte {
	n := src[len(src)-1]
	return src[:len(src)-int(n)]
}

func parseCipher(s string) (typ int, iv, ct, mac []byte, err error) {
	i := strings.IndexByte(s, '.')
	if i < 0 {
		return 0, nil, nil, nil, fmt.Errorf("invalid cipher string %q", s)
	}
	typStr := s[:i]
	typ, err = strconv.Atoi(typStr)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("invalid cipher type %q", typStr)
	}
	s = s[i+1:]

	parts := strings.Split(s, "|")
	if len(parts) != 3 {
		return 0, nil, nil, nil, fmt.Errorf("invalid cipher string %q", s)
	}

	iv, err = b64enc.DecodeString(parts[0])
	if err != nil {
		return 0, nil, nil, nil, err
	}
	ct, err = b64enc.DecodeString(parts[1])
	if err != nil {
		return 0, nil, nil, nil, err
	}
	mac, err = b64enc.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, nil, err
	}
	return typ, iv, ct, mac, err
}

func validMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
