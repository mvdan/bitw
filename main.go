// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/knq/ini"
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

	// TODO: replace this with websocket push syncing; see
	// https://blog.bitwarden.com/live-sync-bitwarden-apps-fb7a54569fea
	syncInterval = 5 * time.Minute
)

// These can be overriden by the config.
var (
	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"

	email = os.Getenv("EMAIL")
)

var (
	config *ini.File
	data   dataFile

	saveData bool
)

type dataFile struct {
	path string

	DeviceID     string
	AccessToken  string
	RefreshToken string
	TokenExpiry  time.Time

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
	if data.RefreshToken == "" {
		if err := login(ctx); err != nil {
			return err
		}
	} else if time.Now().After(data.TokenExpiry) {
		if err := refreshToken(ctx); err != nil {
			return err
		}
	}

	ctx = context.WithValue(ctx, authToken{}, data.AccessToken)
	switch args[0] {
	case "sync":
		if err := sync(ctx); err != nil {
			return err
		}
	default:
		flagSet.Usage()
	}
	return nil
}
