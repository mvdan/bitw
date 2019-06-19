// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"fmt"

	"github.com/godbus/dbus"
)

const dbusName = "org.freedesktop.secrets"

func serveDBus(ctx context.Context) error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}

	srv := &dbusService{}
	conn.Export(srv, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service")

	reply, err := conn.RequestName(dbusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("name already taken")
	}
	fmt.Printf("Listening on %s\n", dbusName)
	select {}
}

type dbusService struct {
	DefaultCollection dbus.ObjectPath
}

func (d *dbusService) OpenSession(algo string, input dbus.Variant) (output dbus.Variant, result dbus.ObjectPath, _ *dbus.Error) {
	switch algo {
	case "plain":
		output = dbus.MakeVariant("")
		result = "/org/freedesktop/secrets/session/default"
		return
	default:
		// TODO: support dh-ietf1024-sha256-aes128-cbc-pkcs7?
		return output, "/", dbus.NewError("org.freedesktop.DBus.Error.NotSupported", nil)
	}
}

func (d *dbusService) SearchItems(fields map[string]string) (unlocked, locked []dbus.ObjectPath, _ *dbus.Error) {
	fmt.Println(fields)
	unlocked = []dbus.ObjectPath{"/org/freedesktop/secrets/collection/default/somesecret"}
	return
}

type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func (d *dbusService) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (secrets map[dbus.ObjectPath]dbusSecret, _ *dbus.Error) {
	fmt.Println(items, session)
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
