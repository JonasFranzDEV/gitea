// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package webauthn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	authn "github.com/duo-labs/webauthn/webauthn"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/setting"
)

func NewWebAuthn() (config *authn.WebAuthn, err error) {
	return authn.New(&authn.Config{
		RPDisplayName: setting.AppName,
		RPID:          setting.WebAuthn.RPID,
		RPOrigin:      setting.WebAuthn.RPOrigin,
		RPIcon:        setting.WebAuthn.RPIcon,
	})
}

type User struct {
	models.User
	credentials   []authn.Credential `xorm:"-"`
	registrations models.U2FRegistrationList
}

func (u *User) LoadCredentials() (err error) {
	u.registrations, err = models.GetU2FRegistrationsByUID(u.ID)
	if err != nil {
		return err
	}
	u.credentials = u.registrations.ToCredentials()
	return nil
}

func (u *User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	if len(u.FullName) != 0 {
		return u.FullName
	}
	return u.Name
}

func (u *User) WebAuthnIcon() string {
	return u.Avatar
}

func (u *User) WebAuthnCredentials() []authn.Credential {
	return u.credentials
}

func (u *User) AddCredential(name string, credential *authn.Credential) error {
	_, err := models.CreateRegistration(&u.User, name, credential)
	return err
}

func (u *User) UpdateCredential(credential *authn.Credential) error {
	for _, reg := range u.registrations {
		if bytes.Equal(reg.KeyID, credential.ID) {
			return models.UpdateU2FRegistrationByID(reg.ID, credential)
		}
	}
	return fmt.Errorf("registration not found")
}
