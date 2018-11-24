// Copyright 2018 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package user

import (
	"fmt"
	"net/url"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"

	"github.com/go-macaron/binding"
)

const (
	tplGrantAccess base.TplName = "user/auth/grant"
)

// TODO move error and responses to SDK or models

// AuthorizeErrorCode represents an error code specified in RFC 6749
type AuthorizeErrorCode string

const (
	ErrorCodeInvalidRequest          AuthorizeErrorCode = "invalid_request"
	ErrorCodeUnauthorizedClient      AuthorizeErrorCode = "unauthorized_client"
	ErrorCodeAccessDenied            AuthorizeErrorCode = "access_denied"
	ErrorCodeUnsupportedResponseType AuthorizeErrorCode = "unsupported_response_type"
	ErrorCodeInvalidScope            AuthorizeErrorCode = "invalid_scope"
	ErrorCodeServerError             AuthorizeErrorCode = "server_error"
	ErrorCodeTemporaryUnavailable    AuthorizeErrorCode = "temporarily_unavailable"
)

// AuthorizeError represents an error type specified in RFC 6749
type AuthorizeError struct {
	ErrorCode        AuthorizeErrorCode `json:"error" form:"error"`
	ErrorDescription string
	State            string
}

// Error returns the error message
func (err AuthorizeError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

// AccessTokenErrorCode represents an error code specified in RFC 6749
type AccessTokenErrorCode string

const (
	AccessTokenErrorCodeInvalidRequest       AccessTokenErrorCode = "invalid_request"
	AccessTokenErrorCodeInvalidClient                             = "invalid_client"
	AccessTokenErrorCodeInvalidGrant                              = "invalid_grant"
	AccessTokenErrorCodeUnauthorizedClient                        = "unauthorized_client"
	AccessTokenErrorCodeUnsupportedGrantType                      = "unsupported_grant_type"
	AccessTokenErrorCodeInvalidScope                              = "invalid_scope"
)

// AccessTokenError represents an error response specified in RFC 6749
type AccessTokenError struct {
	ErrorCode        AccessTokenErrorCode `json:"error" form:"error"`
	ErrorDescription string               `json:"error_description"`
}

// Error returns the error message
func (err AccessTokenError) Error() string {
	return fmt.Sprintf("%s: %s", err.ErrorCode, err.ErrorDescription)
}

// TokenType specifies the kind of token
type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeMAC              = "mac"
)

// AccessTokenResponse represents a successful access token response
type AccessTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   TokenType `json:"token_type"`
	ExpiresIn   int64     `json:"expires_in"`
	// TODO implement RefreshToken
	RefreshToken string `json:"refresh_token"`
}

// AuthorizeOAuth manages authorize requests
func AuthorizeOAuth(ctx *context.Context, form auth.AuthorizationForm) {
	errs := binding.Errors{}
	errs = form.Validate(ctx.Context, errs)

	app, err := models.GetOAuth2ApplicationByClientID(form.ClientID)
	if err != nil {
		if models.IsErrOauthClientIDInvalid(err) {
			handleAuthorizeError(ctx, AuthorizeError{
				ErrorCode:        ErrorCodeUnauthorizedClient,
				ErrorDescription: "Client ID not registered",
				State:            form.State,
			}, "")
			return
		}
		ctx.ServerError("GetOAuth2ApplicationByClientID", err)
		return
	}
	if err := app.LoadUser(); err != nil {
		ctx.ServerError("LoadUser", err)
		return
	}

	if !app.ContainsRedirectURI(form.RedirectURI) {
		handleAuthorizeError(ctx, AuthorizeError{
			ErrorCode:        ErrorCodeInvalidRequest,
			ErrorDescription: "Unregistered redirect uri.",
			State:            form.State,
		}, "")
		return
	}

	if form.ResponseType != "code" {
		handleAuthorizeError(ctx, AuthorizeError{
			ErrorCode:        ErrorCodeUnsupportedResponseType,
			ErrorDescription: "Only code response type is supported.",
			State:            form.State,
		}, form.RedirectURI)
		return
	}

	grant, err := app.GetGrantByUserID(ctx.User.ID)
	if err != nil {
		handleServerError(ctx, form.State, form.RedirectURI)
		return
	}

	// Redirect if user already granted access
	if grant != nil {
		code, err := grant.GenerateNewAuthorizationCode(form.RedirectURI)
		if err != nil {
			handleServerError(ctx, form.State, form.RedirectURI)
			return
		}
		redirect, err := code.GenerateRedirectURI(form.State)
		if err != nil {
			handleServerError(ctx, form.State, form.RedirectURI)
			return
		}
		ctx.Redirect(redirect.String(), 302)
		return
	}

	// show authorize page to grant access
	ctx.Data["Application"] = app
	ctx.Data["RedirectURI"] = form.RedirectURI
	ctx.Data["State"] = form.State
	// TODO document SESSION <=> FORM
	ctx.Session.Set("client_id", app.ClientID)
	ctx.Session.Set("redirect_uri", form.RedirectURI)
	ctx.Session.Set("state", form.State)
	ctx.HTML(200, tplGrantAccess)
}

// GrantApplicationOAuth manages the post request submitted when a user grants access to an application
func GrantApplicationOAuth(ctx *context.Context, form auth.GrantApplicationForm) {
	if ctx.Session.Get("client_id") != form.ClientID || ctx.Session.Get("state") != form.State ||
		ctx.Session.Get("redirect_uri") != form.RedirectURI {
		ctx.Error(400)
		return
	}
	app, err := models.GetOAuth2ApplicationByClientID(form.ClientID)
	if err != nil {
		ctx.ServerError("GetOAuth2ApplicationByClientID", err)
		return
	}
	grant, err := app.CreateGrant(ctx.User.ID)
	if err != nil {
		handleAuthorizeError(ctx, AuthorizeError{
			State:            form.State,
			ErrorDescription: "cannot create grant for user",
			ErrorCode:        ErrorCodeServerError,
		}, form.RedirectURI)
		return
	}
	code, err := grant.GenerateNewAuthorizationCode(form.RedirectURI)
	if err != nil {
		handleServerError(ctx, form.State, form.RedirectURI)
		return
	}
	redirect, err := code.GenerateRedirectURI(form.State)
	if err != nil {
		handleServerError(ctx, form.State, form.RedirectURI)
	}
	ctx.Redirect(redirect.String(), 302)
}

// AccessTokenOAuth manages all access token requests by the client
func AccessTokenOAuth(ctx *context.Context, form auth.AccessTokenForm) {
	app, err := models.GetOAuth2ApplicationByClientID(form.ClientID)
	if err != nil {
		handleAccessTokenError(ctx, AccessTokenError{
			ErrorCode:        AccessTokenErrorCodeInvalidClient,
			ErrorDescription: "cannot load client",
		})
		return
	}
	if !app.ValidateClientSecret([]byte(form.ClientSecret)) {
		handleAccessTokenError(ctx, AccessTokenError{
			ErrorCode:        AccessTokenErrorCodeUnauthorizedClient,
			ErrorDescription: "client is not authorized",
		})
		return
	}
	grant, err := app.GetGrantByUserID(ctx.User.ID)
	if err != nil || grant == nil {
		handleAccessTokenError(ctx, AccessTokenError{
			ErrorCode:        AccessTokenErrorCodeUnauthorizedClient,
			ErrorDescription: "client is not authorized",
		})
		return
	}
	expirationDate := util.TimeStampNow().Add(setting.API.AccessTokenExpirationTime)
	accessToken := &models.AccessToken{
		UID:        ctx.User.ID,
		Grant:      grant,
		GrantID:    grant.ID,
		ValidUntil: &expirationDate,
	}
	// TODO hide access tokens
	// TODO delete expired access token
	if err := models.NewAccessToken(accessToken); err != nil {
		handleAccessTokenError(ctx, AccessTokenError{
			ErrorCode:        AccessTokenErrorCodeInvalidClient,
			ErrorDescription: "cannot create access token",
		})
		return
	}
	ctx.JSON(200, &AccessTokenResponse{
		AccessToken:  accessToken.Sha1,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    setting.API.AccessTokenExpirationTime,
		RefreshToken: "TODO", // TODO integrate refresh tokens
	})
}

func handleAccessTokenError(ctx *context.Context, acErr AccessTokenError) {
	ctx.JSON(400, acErr)
}

func handleServerError(ctx *context.Context, state string, redirectURI string) {
	handleAuthorizeError(ctx, AuthorizeError{
		ErrorCode:        ErrorCodeServerError,
		ErrorDescription: "A server error occurred",
		State:            state,
	}, redirectURI)
}

func handleAuthorizeError(ctx *context.Context, authErr AuthorizeError, redirectURI string) {
	if redirectURI == "" {
		println(authErr.ErrorDescription)
		ctx.ServerError(authErr.ErrorDescription, authErr)
		return
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		ctx.ServerError("url.Parse", err)
		return
	}
	q := redirect.Query()
	q.Set("error", string(authErr.ErrorCode))
	q.Set("error_description", authErr.ErrorDescription)
	q.Set("state", authErr.State)
	redirect.RawQuery = q.Encode()
	ctx.Redirect(redirect.String(), 302)
}