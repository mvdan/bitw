// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type secretCache struct {
	data *dataFile

	_password    []byte // cached, to avoid repeated prompts
	_configEmail string

	// TODO: store these more securely
	key    []byte
	macKey []byte
}

func (c *secretCache) email() string {
	// First try $EMAIL, then the config value, then the synced data value.
	email := os.Getenv("EMAIL")
	if email == "" {
		email = c._configEmail
	}
	if email == "" {
		email = c.data.Sync.Profile.Email
	}
	return email
}

func (c *secretCache) password() ([]byte, error) {
	if c._password != nil {
		return c._password, nil
	}
	if s := os.Getenv("PASSWORD"); s != "" {
		c._password = []byte(s)
		return c._password, nil
	}
	password, err := passwordPrompt("Password")
	if err != nil {
		return nil, err
	}
	c._password = []byte(password)
	return c._password, nil
}

func (c *secretCache) initKeys() error {
	email := c.email()
	if email == "" {
		return fmt.Errorf("need a configured email or $EMAIL to decrypt data")
	}
	password, err := c.password()
	if err != nil {
		return err
	}

	masterKey := deriveMasterKey(password, email, c.data.KDFIterations)

	// We decrypt the decryption key from the synced data, using the key
	// resulting from stretching masterKey. The keys are discarded once we
	// decrypt the final ones.
	key, macKey := stretchKey(masterKey)

	finalKey, err := decryptWith(c.data.Sync.Profile.Key, key, macKey)
	if err != nil {
		return err
	}
	c.key, c.macKey = finalKey[:32], finalKey[32:64]
	return nil
}

func deriveMasterKey(password []byte, email string, iter int) []byte {
	return pbkdf2.Key(password, []byte(strings.ToLower(email)), iter, 32, sha256.New)
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

func (c *secretCache) decryptStr(s CipherString) (string, error) {
	dec, err := c.decrypt(s)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (c *secretCache) decrypt(s CipherString) ([]byte, error) {
	if s.IsZero() {
		return nil, nil
	}
	if err := c.initKeys(); err != nil {
		return nil, err
	}
	return decryptWith(s, c.key, c.macKey)
}

func decryptWith(s CipherString, key, macKey []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.Type {
	case AesCbc256_HmacSha256_B64:
		// continues below
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
