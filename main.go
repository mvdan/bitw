// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const (
	deviceName = "firefox"
	deviceType = "3" // bitwarden's device type for FireFox
	loginScope = "api offline_access"
)

// TODO: move these to a config file
var (
	deviceID = uuid.New().String() // TODO: make this constant
	apiURL   = "https://api.bitwarden.com"
	idtURL   = "https://identity.bitwarden.com"

	email    = os.Getenv("EMAIL")
	password = []byte(os.Getenv("PASSWORD"))
)

func run() error {
	ctx := context.Background()

	var preLogin preLoginResponse
	if err := jsonPOST(ctx, apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return fmt.Errorf("could not pre-login: %v", err)
	}

	// First, we create the master key, with the password, the lowercase
	// email as salt, and the number of iterations the server told us.
	masterKey := pbkdf2.Key(password, []byte(strings.ToLower(email)),
		preLogin.KDFIterations, 32, sha256.New)

	// symmetricKey := randBytes(64)
	// encKey := symmetricKey[:32]
	// macKey := symmetricKey[32:]
	// iv := randBytes(16)

	// Then we create the hashed password, with the master key as password,
	// the password as hash, and just one iteration.
	hashedPassword := b64enc(pbkdf2.Key(masterKey, password,
		1, 32, sha256.New))

	// Now, we request an auth token.
	// For some reason, this endpoint requires url-encoded values, and won't
	// accept JSON.
	tokLoginReq := make(url.Values)
	tokLoginReq.Set("grant_type", "password")
	tokLoginReq.Set("username", email)
	tokLoginReq.Set("password", string(hashedPassword))
	tokLoginReq.Set("scope", loginScope)
	tokLoginReq.Set("client_id", "connector") // seen in bitwarden/jslib
	tokLoginReq.Set("deviceType", deviceType)
	tokLoginReq.Set("deviceIdentifier", deviceID)
	tokLoginReq.Set("deviceName", deviceName)
	tokLogin := make(url.Values)
	if err := queryPOST(ctx, idtURL+"/connect/token", tokLogin, tokLoginReq); err != nil {
		return fmt.Errorf("could not login via password: %v", err)
	}
	return nil
}

var base64Encoding = base64.StdEncoding.Strict()

func b64enc(src []byte) []byte {
	dst := make([]byte, base64Encoding.EncodedLen(len(src)))
	base64Encoding.Encode(dst, src)
	return dst
}

func randBytes(size int) []byte {
	p := make([]byte, size)
	if _, err := rand.Read(p); err != nil {
		panic(err)
	}
	return p
}
