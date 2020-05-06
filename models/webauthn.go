// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"encoding/binary"
	"github.com/duo-labs/webauthn/webauthn"
)

type WebAuthnUser User

func (w WebAuthnUser) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(w.ID))
	return buf
}

func (w WebAuthnUser) WebAuthnName() string {
	return w.Name
}

func (w WebAuthnUser) WebAuthnDisplayName() string {
	return w.FullName
}

func (w WebAuthnUser) WebAuthnIcon() string {
	return w.Avatar
}

func (w WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	panic("implement me")
}

func (w WebAuthnUser) AddCredential(credential webauthn.Credential) {
}
