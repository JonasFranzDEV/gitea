// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"fmt"

	"code.gitea.io/gitea/modules/timeutil"

	"github.com/duo-labs/webauthn/webauthn"
)

// U2FRegistration represents the registration data and counter of a security key
type U2FRegistration struct {
	ID      int64 `xorm:"pk autoincr"`
	Name    string
	UserID  int64 `xorm:"INDEX"`
	Raw     []byte
	Counter uint32 `xorm:"BIGINT"`

	KeyID           []byte `xorm:""`
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte `xorm:"AAGUID"`

	CreatedUnix timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"INDEX updated"`
}

// TableName returns a better table name for U2FRegistration
func (reg U2FRegistration) TableName() string {
	return "u2f_registration"
}

// ToCredential will create new credential struct containing the information saved in the database
func (reg *U2FRegistration) ToCredential() webauthn.Credential {
	fmt.Println(string(reg.PublicKey))
	return webauthn.Credential{
		ID:              reg.KeyID,
		PublicKey:       reg.PublicKey,
		AttestationType: reg.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:    reg.AAGUID,
			SignCount: reg.Counter,
		},
	}
}

func (reg *U2FRegistration) updateCounter(e Engine) error {
	_, err := e.ID(reg.ID).Cols("counter").Update(reg)
	return err
}

// UpdateCounter will update the database value of counter
func (reg *U2FRegistration) UpdateCounter() error {
	return reg.updateCounter(x)
}

// U2FRegistrationList is a list of *U2FRegistration
type U2FRegistrationList []*U2FRegistration

// ToRegistrations will convert all U2FRegistrations to u2f.Registrations
func (list U2FRegistrationList) ToCredentials() []webauthn.Credential {
	regs := make([]webauthn.Credential, 0, len(list))
	for _, reg := range list {
		r := reg.ToCredential()
		regs = append(regs, r)
	}

	return regs
}

func UpdateU2FRegistrationByID(id int64, credential *webauthn.Credential) error {
	return updateU2FRegistrationByCredential(x, id, credential)
}

func updateU2FRegistrationByCredential(e Engine, id int64, credential *webauthn.Credential) (err error) {
	_, err = e.
		ID(id).
		Cols("public_key", "attestation_type", "AAGUID", "counter").
		Update(&U2FRegistration{
			PublicKey:       credential.PublicKey,
			AttestationType: credential.AttestationType,
			AAGUID:          credential.Authenticator.AAGUID,
			Counter:         credential.Authenticator.SignCount,
		})
	return
}

func getU2FRegistrationsByUID(e Engine, uid int64) (U2FRegistrationList, error) {
	regs := make(U2FRegistrationList, 0)
	return regs, e.Where("user_id = ?", uid).Find(&regs)
}

// GetU2FRegistrationByID returns U2F registration by id
func GetU2FRegistrationByID(id int64) (*U2FRegistration, error) {
	return getU2FRegistrationByID(x, id)
}

func getU2FRegistrationByID(e Engine, id int64) (*U2FRegistration, error) {
	reg := new(U2FRegistration)
	if found, err := e.ID(id).Get(reg); err != nil {
		return nil, err
	} else if !found {
		return nil, ErrU2FRegistrationNotExist{ID: id}
	}
	return reg, nil
}

// GetU2FRegistrationsByUID returns all U2F registrations of the given user
func GetU2FRegistrationsByUID(uid int64) (U2FRegistrationList, error) {
	return getU2FRegistrationsByUID(x, uid)
}

func createRegistration(e Engine, user *User, name string, credential *webauthn.Credential) (*U2FRegistration, error) {
	r := &U2FRegistration{
		UserID:          user.ID,
		Name:            name,
		KeyID:           credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		Counter:         credential.Authenticator.SignCount,
	}
	_, err := e.InsertOne(r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// CreateRegistration will create a new U2FRegistration from the given Registration
func CreateRegistration(user *User, name string, credential *webauthn.Credential) (*U2FRegistration, error) {
	return createRegistration(x, user, name, credential)
}

// DeleteRegistration will delete U2FRegistration
func DeleteRegistration(reg *U2FRegistration) error {
	return deleteRegistration(x, reg)
}

func deleteRegistration(e Engine, reg *U2FRegistration) error {
	_, err := e.Delete(reg)
	return err
}
