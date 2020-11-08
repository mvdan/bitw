// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []Cipher
	Domains Domains
}

type CipherString struct {
	Type CipherStringType

	IV, CT, MAC []byte
}

// taken from: https://github.com/bitwarden/jslib/blob/f30d6f8027055507abfdefd1eeb5d9aab25cc601/src/enums/encryptionType.ts
//
//export enum EncryptionType {
//    AesCbc256_B64 = 0,
//    AesCbc128_HmacSha256_B64 = 1,
//    AesCbc256_HmacSha256_B64 = 2,
//    Rsa2048_OaepSha256_B64 = 3,
//    Rsa2048_OaepSha1_B64 = 4,
//    Rsa2048_OaepSha256_HmacSha256_B64 = 5,
//    Rsa2048_OaepSha1_HmacSha256_B64 = 6,
//}
type CipherStringType int

const (
	AesCbc256_B64                     CipherStringType = 0
	AesCbc128_HmacSha256_B64          CipherStringType = 1
	AesCbc256_HmacSha256_B64          CipherStringType = 2
	Rsa2048_OaepSha256_B64            CipherStringType = 3
	Rsa2048_OaepSha1_B64              CipherStringType = 4
	Rsa2048_OaepSha256_HmacSha256_B64 CipherStringType = 5
	Rsa2048_OaepSha1_HmacSha256_B64   CipherStringType = 6
)

func CipherStringTypeParse(str string) (CipherStringType, error) {
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	strType := CipherStringType(val)

	_, ok := parsers[strType]
	if ok {
		return strType, nil
	} else {
		return 0, fmt.Errorf("unsupported cipherstringtype: %v", val)
	}
}

type CipherStringTypeParserFunc func(parts [][]byte) (*CipherString, error)

var parsers = map[CipherStringType]CipherStringTypeParserFunc{
	AesCbc256_B64:            ParseAesCbc256_B64,
	AesCbc128_HmacSha256_B64: ParseAesCbc128_HmacSha256_B64,
	AesCbc256_HmacSha256_B64: ParseAesCbc256_HmacSha256_B64,
	// TODO: implement these:
	//Rsa2048_OaepSha256_B64: someFunc,
	//Rsa2048_OaepSha1_B64: someFunc,
	//Rsa2048_OaepSha256_HmacSha256_B64: someFunc,
	//Rsa2048_OaepSha1_HmacSha256_B64: someFunc,
}

func ParseAesCbc256_HmacSha256_B64(parts [][]byte) (*CipherString, error) {
	if len(parts) != 3 {
		return nil, fmt.Errorf("can not parse: %v", parts)
	}
	s := &CipherString{
		Type: AesCbc256_HmacSha256_B64,
	}

	var err error
	if s.IV, err = b64decode(parts[0]); err != nil {
		return s, err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return s, err
	}
	// TODO: can we verify the MAC here?
	if s.MAC, err = b64decode(parts[2]); err != nil {
		return s, err
	}

	return s, nil
}

func ParseAesCbc128_HmacSha256_B64(parts [][]byte) (*CipherString, error) {
	if len(parts) != 3 {
		return nil, fmt.Errorf("can not parse: %v", parts)
	}

	s := &CipherString{
		Type: AesCbc128_HmacSha256_B64,
	}

	var err error
	if s.IV, err = b64decode(parts[0]); err != nil {
		return s, err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return s, err
	}
	// TODO: can we verify the MAC here?
	if s.MAC, err = b64decode(parts[2]); err != nil {
		return s, err
	}

	return s, nil
}

func ParseAesCbc256_B64(parts [][]byte) (*CipherString, error) {
	if len(parts) != 2 {
		return nil, fmt.Errorf("can not parse: %v", parts)
	}

	s := &CipherString{
		Type: AesCbc256_B64,
	}

	var err error
	if s.IV, err = b64decode(parts[0]); err != nil {
		return s, err
	}
	if s.CT, err = b64decode(parts[1]); err != nil {
		return s, err
	}

	return s, nil
}

func (i CipherStringType) String() string {
	switch i {
	case AesCbc256_B64:
		return "AesCbc256_B64"
	case AesCbc128_HmacSha256_B64:
		return "AesCbc128_HmacSha256_B64"
	case AesCbc256_HmacSha256_B64:
		return "AesCbc256_HmacSha256_B64"
	case Rsa2048_OaepSha256_B64:
		return "Rsa2048_OaepSha256_B64"
	case Rsa2048_OaepSha1_B64:
		return "Rsa2048_OaepSha1_B64"
	case Rsa2048_OaepSha256_HmacSha256_B64:
		return "Rsa2048_OaepSha256_HmacSha256_B64"
	case Rsa2048_OaepSha1_HmacSha256_B64:
		return "Rsa2048_OaepSha1_HmacSha256_B64"
	default:
		return "unknown"
	}
}

func (s CipherString) MarshalText() ([]byte, error) {
	if s.Type == 0 {
		return []byte(fmt.Sprintf("%d.%s|%s",
			s.Type,
			b64enc.EncodeToString(s.IV),
			b64enc.EncodeToString(s.CT),
		)), nil
	}
	return []byte(fmt.Sprintf("%d.%s|%s|%s",
		s.Type,
		b64enc.EncodeToString(s.IV),
		b64enc.EncodeToString(s.CT),
		b64enc.EncodeToString(s.MAC),
	)), nil
}

func (s *CipherString) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	i := bytes.IndexByte(data, '.')
	if i < 0 {
		return fmt.Errorf("invalid cipher string %q", data)
	}
	typStr := string(data[:i])
	var err error
	if s.Type, err = CipherStringTypeParse(typStr); err != nil {
		return fmt.Errorf("invalid cipher type %q", typStr)
	}
	data = data[i+1:]

	parts := bytes.Split(data, []byte("|"))

	s2, err := parsers[s.Type](parts)
	if err != nil {
		return err
	}

	// hack for now:
	s.Type = s2.Type
	s.IV = s2.IV
	s.MAC = s2.MAC
	s.CT = s2.CT

	return err
}

func b64decode(src []byte) ([]byte, error) {
	dst := make([]byte, b64enc.DecodedLen(len(src)))
	n, err := b64enc.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	dst = dst[:n]
	return dst, nil
}

func b64decodeStr(src string) ([]byte, error) {
	return b64decode([]byte(src))
}

type Organization struct {
	Object          string
	Id              uuid.UUID
	Name            string
	UseGroups       bool
	UseDirectory    bool
	UseEvents       bool
	UseTotp         bool
	Use2fa          bool
	UseApi          bool
	UsersGetPremium bool
	SelfHost        bool
	Seats           int
	MaxCollections  int
	MaxStorageGb    int
	Key             string
	Status          int
	Type            int
	Enabled         bool
}

type Profile struct {
	ID                 uuid.UUID
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                CipherString
	PrivateKey         CipherString
	SecurityStamp      string
	Organizations      []Organization
}

type Folder struct {
	ID           uuid.UUID
	Name         string
	RevisionDate time.Time
}

type Domains struct {
	EquivalentDomains       []string
	GlobalEquivalentDomains []GlobalEquivalentDomains
}

type GlobalEquivalentDomains struct {
	Type     int
	Domains  []string
	Excluded bool
}

type Cipher struct {
	Type                CipherType
	FolderID            uuid.UUID
	OrganizationID      uuid.UUID
	Favorite            bool
	Edit                bool
	ID                  uuid.UUID
	Attachments         interface{} // TODO
	OrganizationUseTotp bool
	RevisionDate        time.Time
	CollectionIDs       []string

	Card       Card
	Fields     []Field
	Identity   Identity
	Login      Login
	Name       CipherString
	Notes      CipherString
	SecureNote SecureNote
}

type CipherType int

const (
	_ CipherType = iota
	CipherLogin
	CipherCard
	CipherIdentity
	CipherNote
)

type Card struct {
	CardholderName CipherString
	Brand          CipherString
	Number         CipherString
	ExpMonth       CipherString
	ExpYear        CipherString
	Code           CipherString
}

type Identity struct {
	Title      CipherString
	FirstName  CipherString
	MiddleName CipherString
	LastName   CipherString

	Username       CipherString
	Company        CipherString
	SSN            CipherString
	PassportNumber CipherString
	LicenseNumber  CipherString

	Email      CipherString
	Phone      CipherString
	Address1   CipherString
	Address2   CipherString
	Address3   CipherString
	City       CipherString
	State      CipherString
	PostalCode CipherString
	Country    CipherString
}

func (c *Cipher) Match(attr, value string) bool {
	got := ""
	var err error
	switch attr {
	case "id":
		got = c.ID.String()
	case "name":
		got, err = decryptStr(c.Name)
	case "username":
		got, err = decryptStr(c.Login.Username)
	default:
		return false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt %s: %v\n", attr, err)
		return false
	}
	return got == value
}

type Field struct {
	Type  FieldType
	Name  CipherString
	Value CipherString
}

type FieldType int

type Login struct {
	Password CipherString
	Totp     string
	URI      CipherString
	URIs     []URI
	Username CipherString
}

type URI struct {
	URI   string
	Match URIMatch
}

type URIMatch int

type SecureNote struct {
	Type SecureNoteType
}

type SecureNoteType int

func sync(ctx context.Context) error {
	now := time.Now().UTC()
	if err := jsonGET(ctx, apiURL+"/sync", &data.Sync); err != nil {
		return fmt.Errorf("could not sync: %v", err)
	}
	data.LastSync = now
	saveData = true
	return nil
}
