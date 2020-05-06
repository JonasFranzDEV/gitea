// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package migrations

import (
	"code.gitea.io/gitea/modules/setting"
	"crypto/elliptic"
	"fmt"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/tstranex/u2f"
	"xorm.io/xorm"
)

type U2FRegistration struct {
	ID      int64 `xorm:"pk autoincr"`
	Raw     []byte
	Counter uint32 `xorm:"BIGINT"`
}

func (reg U2FRegistration) TableName() string {
	return "u2f_registration"
}

func convertU2FToWebAuthn(x *xorm.Engine) error {
	var limit = setting.Database.IterateBufferSize
	if limit <= 0 {
		limit = 50
	}

	i := 0
	for {
		regs := make([]U2FRegistration, 0, limit)
		if err := x.Limit(limit, i).Asc("id").Find(&regs); err != nil {
			return fmt.Errorf("find: %v", err)
		}
		if len(regs) == 0 {
			break
		}
		for _, reg := range regs {
			r := new(u2f.Registration)
			if err := r.UnmarshalBinary(reg.Raw); err != nil {
				return err
			}
			credential := &webauthn.Credential{
				ID:              r.KeyHandle,
				PublicKey:       elliptic.Marshal(r.PubKey.Curve, r.PubKey.X, r.PubKey.Y),
				AttestationType: "none",
				Authenticator: webauthn.Authenticator{
					AAGUID:    r.AttestationCert.Raw,
					SignCount: reg.Counter,
				},
			}
			fmt.Sprintf("%v\n", credential)
		}

	}
	return nil
}
