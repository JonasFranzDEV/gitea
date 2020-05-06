// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package migrations

import (
	"crypto/elliptic"
	"fmt"

	"github.com/tstranex/u2f"
	"xorm.io/xorm"

	"code.gitea.io/gitea/modules/setting"
)

type U2FRegistration struct {
	ID              int64 `xorm:"pk autoincr"`
	Raw             []byte
	KeyID           []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte `xorm:"AAGUID"`
}

func (reg U2FRegistration) TableName() string {
	return "u2f_registration"
}

func convertU2FToWebAuthn(x *xorm.Engine) error {
	if err := x.Sync2(&U2FRegistration{}); err != nil {
		return err
	}
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
			x.Cols("key_id", "public_key", "attestation_type", "AAGUID").Update(&U2FRegistration{
				KeyID:           r.KeyHandle,
				PublicKey:       elliptic.Marshal(r.PubKey.Curve, r.PubKey.X, r.PubKey.Y),
				AttestationType: "none",
				AAGUID:          make([]byte, 16),
			}, reg)
		}
		i += len(regs)

	}
	// TODO drop raw column
	return nil
}
