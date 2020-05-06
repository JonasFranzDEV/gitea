// Copyright 2018 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package setting

import (
	"errors"

	"github.com/duo-labs/webauthn/protocol"
	authn "github.com/duo-labs/webauthn/webauthn"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth"
	"code.gitea.io/gitea/modules/auth/webauthn"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/setting"
)

// U2FRegister initializes the webauthn registration procedure
func U2FRegister(ctx *context.Context, form auth.U2FRegistrationForm) {
	if form.Name == "" {
		ctx.Error(409)
		return
	}
	authUser := &webauthn.User{
		User: *ctx.User,
	}
	if err := authUser.LoadCredentials(); err != nil {
		ctx.ServerError("LoadCredentials", err)
		return
	}
	web, err := webauthn.NewWebAuthn()
	if err != nil {
		ctx.ServerError("NewWebAuthn", err)
		return
	}
	options, sessionData, err := web.BeginRegistration(authUser)
	if err != nil {
		ctx.ServerError("BeginRegistration", err)
		return
	}
	err = ctx.Session.Set("webauthnSessionData", sessionData)
	if err != nil {
		ctx.ServerError("Session.Set", err)
		return
	}
	regs, err := models.GetU2FRegistrationsByUID(ctx.User.ID)
	if err != nil {
		ctx.ServerError("GetU2FRegistrationsByUID", err)
		return
	}
	for _, reg := range regs {
		if reg.Name == form.Name {
			ctx.Error(409, "Name already taken")
			return
		}
	}
	err = ctx.Session.Set("u2fName", form.Name)
	if err != nil {
		ctx.ServerError("", err)
		return
	}
	ctx.JSON(200, options)
}

// U2FRegisterPost receives the response of the security key
func U2FRegisterPost(ctx *context.Context) {
	parsedResponse, err := protocol.ParseCredentialCreationResponse(ctx.Req.Request)
	if err != nil {
		ctx.ServerError("ParseCredentialCreationResponseBody", err)
		return
	}
	authUser := &webauthn.User{
		User: *ctx.User,
	}
	if err := authUser.LoadCredentials(); err != nil {
		ctx.ServerError("LoadCredentials", err)
		return
	}
	sessionData, ok := ctx.Session.Get("webauthnSessionData").(*authn.SessionData)
	u2fName := ctx.Session.Get("u2fName")
	if !ok || sessionData == nil || u2fName == nil {
		ctx.ServerError("U2FRegisterPost", errors.New("not in U2F session"))
		return
	}
	name := u2fName.(string)
	web, err := webauthn.NewWebAuthn()
	if err != nil {
		ctx.ServerError("NewWebAuthn", err)
		return
	}
	credential, err := web.CreateCredential(authUser, *sessionData, parsedResponse)
	if err := authUser.AddCredential(name, credential); err != nil {
		ctx.ServerError("AddCredential", err)
		return
	}
	ctx.Status(200)
}

// U2FDelete deletes an security key by id
func U2FDelete(ctx *context.Context, form auth.U2FDeleteForm) {
	reg, err := models.GetU2FRegistrationByID(form.ID)
	if err != nil {
		if models.IsErrU2FRegistrationNotExist(err) {
			ctx.Status(200)
			return
		}
		ctx.ServerError("GetU2FRegistrationByID", err)
		return
	}
	if reg.UserID != ctx.User.ID {
		ctx.Status(401)
		return
	}
	if err := models.DeleteRegistration(reg); err != nil {
		ctx.ServerError("DeleteRegistration", err)
		return
	}
	ctx.JSON(200, map[string]interface{}{
		"redirect": setting.AppSubURL + "/user/settings/security",
	})
}
