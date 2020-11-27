// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
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
	keyCipher := c.data.Sync.Profile.Key
	switch keyCipher.Type {
	case AesCbc256_B64, AesCbc256_HmacSha256_B64:
	default:
		return fmt.Errorf("unsupported key cipher type %q", keyCipher.Type)
	}

	email := c.email()
	if email == "" {
		return fmt.Errorf("need a configured email or $EMAIL to decrypt data")
	}
	password, err := c.password()
	if err != nil {
		return err
	}

	masterKey := deriveMasterKey(password, email, c.data.KDFIterations)

	// This bit of code can help create a random key and encrypt it with a
	// given email/password. Useful for creating test data for TestCipherString.
	// rnd := make([]byte, 32) // or 64 to include a mac key
	// if _, err := io.ReadFull(rand.Reader, rnd); err != nil {
	// 	return err
	// }
	// // use "key, macKey := stretchKey(masterKey)" for a Hmac cipher type
	// k, err := encryptWith(rnd, AesCbc256_B64, masterKey, nil)
	// if err != nil {
	// 	return err
	// }
	// println(k.String())

	var finalKey []byte
	switch keyCipher.Type {
	case AesCbc256_B64:
		finalKey, err = decryptWith(keyCipher, masterKey, nil)
		if err != nil {
			return err
		}
	case AesCbc256_HmacSha256_B64:
		// We decrypt the decryption key from the synced data, using the key
		// resulting from stretching masterKey. The keys are discarded once we
		// obtain the final ones.
		key, macKey := stretchKey(masterKey)

		finalKey, err = decryptWith(keyCipher, key, macKey)
		if err != nil {
			return err
		}
	}

	switch len(finalKey) {
	case 32:
		c.key = finalKey
	case 64:
		c.key, c.macKey = finalKey[:32], finalKey[32:64]
	default:
		return fmt.Errorf("invalid key length: %d", len(finalKey))
	}

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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.Type {
	case AesCbc256_B64, AesCbc256_HmacSha256_B64:
		// continues below
	default:
		return nil, fmt.Errorf("decrypt: unsupported cipher type %q", s.Type)
	}

	if s.Type == AesCbc256_HmacSha256_B64 {
		if len(s.MAC) == 0 || len(macKey) == 0 {
			return nil, fmt.Errorf("decrypt: cipher string type expects a MAC")
		}
		var msg []byte
		msg = append(msg, s.IV...)
		msg = append(msg, s.CT...)
		if !validMAC(msg, s.MAC, macKey) {
			return nil, fmt.Errorf("decrypt: MAC mismatch")
		}
	}

	mode := cipher.NewCBCDecrypter(block, s.IV)
	dst := make([]byte, len(s.CT))
	mode.CryptBlocks(dst, s.CT)
	dst, err = unpad(dst, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func (c *secretCache) encrypt(data []byte) (CipherString, error) {
	// Same default as vault.bitwarden.com.
	return c.encryptType(data, AesCbc256_HmacSha256_B64)
}

func (c *secretCache) encryptType(data []byte, typ CipherStringType) (CipherString, error) {
	if len(data) == 0 {
		return CipherString{}, nil
	}
	if err := c.initKeys(); err != nil {
		return CipherString{}, err
	}
	return encryptWith(data, typ, c.key, c.macKey)
}

func encryptWith(data []byte, typ CipherStringType, key, macKey []byte) (CipherString, error) {
	s := CipherString{}
	switch typ {
	case AesCbc256_B64, AesCbc256_HmacSha256_B64:
	default:
		return s, fmt.Errorf("encrypt: unsupported cipher type %q", s.Type)
	}
	s.Type = typ
	data = pad(data, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return s, err
	}
	s.IV = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, s.IV); err != nil {
		return s, err
	}
	s.CT = make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, s.IV)
	mode.CryptBlocks(s.CT, data)

	if typ == AesCbc256_HmacSha256_B64 {
		if len(macKey) == 0 {
			return s, fmt.Errorf("encrypt: cipher string type expects a MAC")
		}
		var macMessage []byte
		macMessage = append(macMessage, s.IV...)
		macMessage = append(macMessage, s.CT...)
		mac := hmac.New(sha256.New, macKey)
		mac.Write(macMessage)
		s.MAC = mac.Sum(nil)
	}

	return s, nil
}

func unpad(src []byte, size int) ([]byte, error) {
	n := src[len(src)-1]
	if len(src)%size != 0 {
		return nil, fmt.Errorf("expected PKCS7 padding for block size %d, but have %d bytes", size, len(src))
	}
	if len(src) <= int(n) {
		return nil, fmt.Errorf("cannot unpad %d bytes out of a total of %d", n, len(src))
	}
	src = src[:len(src)-int(n)]
	return src, nil
}

func pad(src []byte, size int) []byte {
	// Note that we always pad, even if rem==0. This is because unpad must
	// always remove at least one byte to be unambiguous.
	rem := len(src) % size
	n := size - rem
	if n > math.MaxUint8 {
		panic(fmt.Sprintf("cannot pad over %d bytes, but got %d", math.MaxUint8, n))
	}
	padded := make([]byte, len(src)+n)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func validMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
