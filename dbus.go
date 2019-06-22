// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/godbus/dbus"
)

const (
	dbusName  = "org.freedesktop.secrets"
	objPrefix = "/org/freedesktop/secrets"
)

var (
	errNotSupported = dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
	errNoSuchObject = dbus.NewError("org.freedesktop.Secret.Error.NoSuchObject", nil)
	errAlreadyTaken = fmt.Errorf("dbus name %s already taken", dbusName)
)

func dbusErrorf(format string, args ...interface{}) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{
		fmt.Sprintf(format, args...),
	})
}

func objPath(suffix string) dbus.ObjectPath {
	return dbus.ObjectPath(objPrefix + suffix)
}

func serveDBus(ctx context.Context) error {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return err
	}
	if err := conn.Hello(); err != nil {
		return err
	}

	srv := &dbusService{}
	conn.Export(srv, objPrefix, "org.freedesktop.Secret.Service")

	reply, err := conn.RequestName(dbusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errAlreadyTaken
	}

	fmt.Printf("Listening on %s\n", dbusName)
	<-ctx.Done()
	conn.Close()
	return ctx.Err()
}

type dbusService struct{}

func (d *dbusService) OpenSession(algo string, input dbus.Variant) (output dbus.Variant, result dbus.ObjectPath, _ *dbus.Error) {
	switch algo {
	case "plain":
		return dbus.MakeVariant(""), objPath("/session/default"), nil
	default:
		// TODO: support dh-ietf1024-sha256-aes128-cbc-pkcs7?
		return output, "/", errNotSupported
	}
}

func (d *dbusService) SearchItems(attributes map[string]string) (unlocked, locked []dbus.ObjectPath, _ *dbus.Error) {
Ciphers:
	for _, cipher := range data.Sync.Ciphers {
		for attr, value := range attributes {
			if !cipher.Match(attr, value) {
				continue Ciphers
			}
		}
		// Object paths can only contain letters, numbers, and
		// underscores.
		id := dbusID(cipher.ID)
		unlocked = append(unlocked, objPath("/collections/default/"+id))
	}
	return
}

func dbusID(id string) string {
	return strings.Replace(id, "-", "", -1)
}

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (d *dbusService) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (secrets map[dbus.ObjectPath]dbusSecret, _ *dbus.Error) {
	secrets = make(map[dbus.ObjectPath]dbusSecret)
	for _, item := range items {
		id := path.Base(string(item))

		var found Cipher
		for _, cipher := range data.Sync.Ciphers {
			if dbusID(cipher.ID) == id {
				found = cipher
				break
			}
		}
		if found.ID == "" {
			return nil, errNoSuchObject
		}
		password, err := decrypt(found.Login.Password)
		if err != nil {
			return nil, dbusErrorf("%s", err)
		}
		secrets[item] = dbusSecret{
			Session:     session,
			Value:       password,
			ContentType: "text/plain",
		}
	}
	return
}
