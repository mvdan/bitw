// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/godbus/dbus"
)

const (
	dbusName  = "org.freedesktop.secrets"
	objPrefix = "/org/freedesktop/secrets"
)

var (
	errNotSupported = dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
	errAlreadyTaken = fmt.Errorf("dbus name %s already taken", dbusName)
)

func objPath(suffix string) dbus.ObjectPath {
	return dbus.ObjectPath(objPrefix + suffix)
}

func serveDBus(ctx context.Context) error {
	// TODO: use SessionBusPrivate
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	defer conn.Close()

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
	// TODO: use ctx
	select {} // block forever; handling is via callbacks
}

type dbusService struct {
	DefaultCollection dbus.ObjectPath
}

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
		id := strings.Replace(cipher.ID, "-", "", -1)
		unlocked = append(unlocked, objPath("/collections/default/"+id))
	}
	return
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
		secrets[item] = dbusSecret{
			Session:     session,
			Value:       []byte("supersecret"),
			ContentType: "text/plain",
		}
	}
	return
}
