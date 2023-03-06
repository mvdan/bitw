// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type preLoginRequest struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF           int
	KDFIterations int
}

type tokLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
}

const (
	// deviceName should probably be like "Linux", "Android", etc, but this
	// helps the human user differentiate bitw logins from those made by the
	// official clients.
	deviceName       = "bitw"
	loginScope       = "api offline_access"
	loginApiKeyScope = "api"
)

func deviceType() string {
	// The enum strings come from https://github.com/bitwarden/server/blob/b19628c6f85a2cd5f1950ac222ba14840a88894d/src/Core/Enums/DeviceType.cs.
	switch runtime.GOOS {
	case "linux":
		return "8" // Linux Desktop
	case "darwin":
		return "7" // MacOS Desktop
	case "windows":
		return "6" // Windows Desktop
	default:
		return "14" // Unknown Browser, since we don't have a better fallback
	}
}

func login(ctx context.Context, retryWithApiKey bool) error {
	email := secrets.email()
	if email == "" {
		return fmt.Errorf("need a configured email or $EMAIL to log in")
	}

	var preLogin preLoginResponse
	if err := jsonPOST(ctx, apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return fmt.Errorf("could not pre-login: %v", err)
	}
	globalData.KDF = preLogin.KDF
	globalData.KDFIterations = preLogin.KDFIterations
	saveData = true

	var values url.Values
	if !retryWithApiKey {
		password, err := secrets.password()
		if err != nil {
			return err
		}

		// First, we create the master key, with the password, the lowercase
		// email as salt, and the number of iterations the server told us.
		masterKey := deriveMasterKey(password, email, preLogin.KDFIterations)

		// Then we create the hashed password, with the master key as password,
		// the password as hash, and just one iteration.
		hashedPassword := b64enc.EncodeToString(pbkdf2.Key(masterKey, password,
			1, 32, sha256.New))

		// Now, we request an auth token.
		// For some reason, this endpoint requires url-encoded values, and won't
		// accept JSON. But of course, the response is JSON.
		values = urlValues(
			"grant_type", "password",
			"username", email,
			"password", string(hashedPassword),
			"scope", loginScope,
			"client_id", "connector", // seen in bitwarden/jslib
			"deviceType", deviceType(),
			"deviceName", deviceName,
			"deviceIdentifier", globalData.DeviceID,
		)
	} else {
		clientId, err := secrets.clientId()
		if err != nil {
			return err
		}

		clientSecret, err := secrets.clientSecret()
		if err != nil {
			return err
		}

		values = urlValues(
			"client_id", string(clientId[:]),
			"client_secret", string(clientSecret[:]),
			"scope", loginApiKeyScope,
			"grant_type", "client_credentials",
			"deviceType", deviceType(),
			"deviceName", deviceName,
			"deviceIdentifier", globalData.DeviceID,
		)
	}

	now := time.Now().UTC()
	var tokLogin tokLoginResponse
	err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values)
	errsc, ok := err.(*errStatusCode)
	if ok && bytes.Contains(errsc.body, []byte("TwoFactor")) {
		var twoFactor twoFactorResponse
		if err := json.Unmarshal(errsc.body, &twoFactor); err != nil {
			return err
		}
		provider, token, err := twoFactorPrompt(&twoFactor)
		if err != nil {
			return fmt.Errorf("could not obtain two-factor auth token: %v", err)
		}
		values.Set("twoFactorProvider", strconv.Itoa(int(provider)))
		values.Set("twoFactorToken", string(token))
		values.Set("twoFactorRemember", "1") // TODO: probably make this configurable
		tokLogin = tokLoginResponse{}
		if err := jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values); err != nil {
			return fmt.Errorf("could not login via two-factor: %v", err)
		}
	} else if err != nil && strings.Contains(err.Error(), "Captcha required.") {
		fmt.Println("The server presented us with a captcha.")
		fmt.Println("The best way to prevent future captcha is by login at least one time via api-key.")
		fmt.Println("You can read on how to obtain the keys at: https://bitwarden.com/help/personal-api-key/")
		return login(ctx, true)
	} else if err != nil {
		return fmt.Errorf("could not login via password: %v", err)
	}
	globalData.AccessToken = tokLogin.AccessToken
	globalData.RefreshToken = tokLogin.RefreshToken
	globalData.TokenExpiry = now.Add(time.Duration(tokLogin.ExpiresIn) * time.Second)
	saveData = true
	return nil
}

type TwoFactorProvider int

// Enum values copied from https://github.com/bitwarden/server/blob/f311f40d9333442a727eb8b77f3859597de199da/src/Core/Enums/TwoFactorProviderType.cs.
// Do not use iota, to clarify that these integer values are defined elsewhere.
const (
	Authenticator         TwoFactorProvider = 0
	Email                 TwoFactorProvider = 1
	Duo                   TwoFactorProvider = 2
	YubiKey               TwoFactorProvider = 3
	U2f                   TwoFactorProvider = 4
	Remember              TwoFactorProvider = 5
	OrganizationDuo       TwoFactorProvider = 6
	WebAuthn              TwoFactorProvider = 7
	_TwoFactorProviderMax                   = 8
)

func (t *TwoFactorProvider) UnmarshalText(text []byte) error {
	i, err := strconv.Atoi(string(text))
	if err != nil || i < 0 || i >= _TwoFactorProviderMax {
		return fmt.Errorf("invalid two-factor auth provider: %q", text)
	}
	*t = TwoFactorProvider(i)
	return nil
}

func (t TwoFactorProvider) Line(extra map[string]interface{}) string {
	switch t {
	case Authenticator:
		return "Six-digit authenticator token"
	case Email:
		emailHint := extra["Email"].(string)
		return fmt.Sprintf("Six-digit email token (%s)", emailHint)
	}
	return fmt.Sprintf("unsupported two factor auth provider %d", t)
}

type twoFactorResponse struct {
	TwoFactorProviders2 map[TwoFactorProvider]map[string]interface{}
}

func twoFactorPrompt(resp *twoFactorResponse) (TwoFactorProvider, []byte, error) {
	var selected TwoFactorProvider
	switch len(resp.TwoFactorProviders2) {
	case 0:
		return -1, nil, fmt.Errorf("API requested 2fa but has no available providers")
	case 1:
		// Use the single available provider.
		for provider := range resp.TwoFactorProviders2 {
			selected = provider
			break
		}
	default:
		// List all available providers, and make the user choose.
		// Don't range over the map directly, as the order wouldn't be stable.
		var available []TwoFactorProvider
		for pv := TwoFactorProvider(0); pv < _TwoFactorProviderMax; pv++ {
			extra, ok := resp.TwoFactorProviders2[pv]
			if !ok {
				continue
			}
			available = append(available, pv)
			fmt.Fprintf(os.Stderr, "%d) %s\n", len(available), pv.Line(extra))
		}
		input, err := readLine(fmt.Sprintf("Select a two-factor auth provider [1-%d]", len(available)))
		if err != nil {
			return -1, nil, err
		}
		i, err := strconv.Atoi(string(input))
		if err != nil {
			return -1, nil, err
		}
		if i <= 0 || i > len(available) {
			return -1, nil, fmt.Errorf("selected option %d is not within the range [1-%d]", i, len(available))
		}
		selected = available[i-1]
	}
	token, err := passwordPrompt(selected.Line(resp.TwoFactorProviders2[selected]))
	if err != nil {
		return -1, nil, err
	}
	return selected, token, nil
}

func refreshToken(ctx context.Context) error {
	return nil
}

func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

var b64enc = base64.StdEncoding.Strict()
