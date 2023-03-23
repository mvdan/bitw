// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type KDFType int

const (
	KDFTypePBKDF2   KDFType = 0
	KDFTypeArgon2id KDFType = 1
)

type secretCache struct {
	data *dataFile

	_password     []byte // cached, to avoid repeated prompts
	_configEmail  string
	_clientId     []byte
	_clientSecret []byte

	// TODO: store these more securely
	key    []byte
	macKey []byte

	// should we also store this as bytes and then decode on every use?
	privateKey *rsa.PrivateKey
	orgKeys    map[string][]byte
	orgMacKeys map[string][]byte
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

func (c *secretCache) clientId() ([]byte, error) {
	if c._clientId != nil {
		return c._clientId, nil
	}
	if s := os.Getenv("CLIENT_ID"); s != "" {
		c._clientId = []byte(s)
		return c._clientId, nil
	}
	clientId, err := passwordPrompt("client_id")
	if err != nil {
		return nil, err
	}
	c._clientId = []byte(clientId)
	return c._clientId, nil
}

func (c *secretCache) clientSecret() ([]byte, error) {
	if c._clientSecret != nil {
		return c._clientSecret, nil
	}
	if s := os.Getenv("CLIENT_SECRET"); s != "" {
		c._clientSecret = []byte(s)
		return c._clientSecret, nil
	}
	clientSecret, err := passwordPrompt("client_secret")
	if err != nil {
		return nil, err
	}
	c._clientSecret = []byte(clientSecret)
	return c._clientSecret, nil
}

func (c *secretCache) initKeys() error {
	if c.key != nil {
		return nil
	}

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

	masterKey, err := deriveMasterKey(password, email, c.data.KDF, c.data.KDFIterations, c.data.KDFMemory, c.data.KDFParallelism)
	if err != nil {
		return err
	}

	// This bit of code can help create a random key and encrypt it with a
	// given email/password. Useful for creating test data for TestCipherString.
	// rnd := make([]byte, 32) // or 64 to include a mac key
	// if _, err := io.ReadFull(cryptorand.Reader, rnd); err != nil {
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

	if !c.data.Sync.Profile.PrivateKey.IsZero() {
		pkcs8PrivateKey, err := secrets.decrypt(c.data.Sync.Profile.PrivateKey, nil)
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(pkcs8PrivateKey)
		if err != nil {
			return err
		}
		c.privateKey = key.(*rsa.PrivateKey)
		c.orgKeys = make(map[string][]byte)
		c.orgMacKeys = make(map[string][]byte)

		for _, organization := range c.data.Sync.Profile.Organizations {
			// the first byte is the encryption type (always 4 at the moment)
			// the second byte is a separator
			var keyString = organization.Key[2:]

			decodedData, err := base64.StdEncoding.DecodeString(keyString)
			if err != nil {
				return err
			}

			res, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.privateKey, decodedData, nil)
			if err != nil {
				return err
			}

			c.orgKeys[organization.Id.String()] = res[0:32]
			c.orgMacKeys[organization.Id.String()] = res[32:64]
		}
	}

	return nil
}

func deriveMasterKey(password []byte, email string, kdfType KDFType, iter int, mem int, par int) ([]byte, error) {
	switch kdfType {
	case KDFTypePBKDF2:
		return pbkdf2.Key(password, []byte(strings.ToLower(email)), iter, 32, sha256.New), nil
	case KDFTypeArgon2id:
		var salt [32]byte = sha256.Sum256([]byte(strings.ToLower(email)))
		return argon2.IDKey(password, salt[:], uint32(iter), uint32(mem*1024), uint8(par), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdfType)
	}
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

func (c *secretCache) decryptStr(s CipherString, orgID *uuid.UUID) (string, error) {
	dec, err := c.decrypt(s, orgID)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func (c *secretCache) decrypt(s CipherString, orgID *uuid.UUID) ([]byte, error) {
	if s.IsZero() {
		return nil, nil
	}
	if err := c.initKeys(); err != nil {
		return nil, err
	}
	if orgID != nil {
		return decryptWith(s, c.orgKeys[orgID.String()], c.orgMacKeys[orgID.String()])
	} else {
		return decryptWith(s, c.key, c.macKey)
	}
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
	dst, err = unpadPKCS7(dst, aes.BlockSize)
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
	data = padPKCS7(data, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return s, err
	}
	s.IV = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cryptorand.Reader, s.IV); err != nil {
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

func unpadPKCS7(src []byte, size int) ([]byte, error) {
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

func padPKCS7(src []byte, size int) []byte {
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

type dhGroup struct {
	g, p, pMinus1 *big.Int
}

var bigOne = big.NewInt(1)

func (dg *dhGroup) NewKeypair() (private, public *big.Int, err error) {
	for {
		if private, err = cryptorand.Int(cryptorand.Reader, dg.pMinus1); err != nil {
			return nil, nil, err
		}
		if private.Sign() > 0 {
			break
		}
	}
	public = new(big.Int).Exp(dg.g, private, dg.p)
	return private, public, nil
}

func (dg *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Cmp(bigOne) <= 0 || theirPublic.Cmp(dg.pMinus1) >= 0 {
		return nil, errors.New("DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, dg.p), nil
}

func rfc2409SecondOakleyGroup() *dhGroup {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	return &dhGroup{
		g:       new(big.Int).SetInt64(2),
		p:       p,
		pMinus1: new(big.Int).Sub(p, bigOne),
	}
}

func (dg *dhGroup) keygenHKDFSHA256AES128(theirPublic *big.Int, myPrivate *big.Int) ([]byte, error) {
	sharedSecret, err := dg.diffieHellman(theirPublic, myPrivate)
	if err != nil {
		return nil, err
	}

	r := hkdf.New(sha256.New, sharedSecret.Bytes(), nil, nil)
	aesKey := make([]byte, 16)
	if _, err := io.ReadFull(r, aesKey); err != nil {
		return nil, err
	}
	return aesKey, nil
}

func unauthenticatedAESCBCEncrypt(data, key []byte) (iv, ciphertext []byte, _ error) {
	data = padPKCS7(data, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	ivSize := aes.BlockSize
	iv = make([]byte, ivSize)
	ciphertext = make([]byte, len(data))
	if _, err := io.ReadFull(cryptorand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return iv, ciphertext, nil
}

// Unused for now; can be useful in the future, for e.g. storing secrets.
func unauthenticatedAESCBCDecrypt(iv, ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv length does not match AES block size")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of AES block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext) // decrypt in-place
	data, err := unpadPKCS7(ciphertext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return data, nil
}
