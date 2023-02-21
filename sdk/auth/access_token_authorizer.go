package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"golang.org/x/oauth2"
)

// Copyright (c) HashiCorp Inc. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AccessTokenAuthorizerOptions struct {
	// Api describes the Azure API being used
	Api environments.Api

	// TokenMap is a map of access tokens (JWT) issued by the Microsoft Identity Platform, where the key is the api's name, and the value is the token.
	TokenMap map[string][]byte
}

// NewAccessTokenAuthorizer returns an Authorizer which authenticates using the Access Token.
func NewAccessTokenAuthorizer(ctx context.Context, options AccessTokenAuthorizerOptions) (Authorizer, error) {
	token, ok := options.TokenMap[options.Api.Name()]
	if !ok {
		return nil, fmt.Errorf("no token configured for API name %s", options.Api.Name())
	}
	tk, _, err := jwt.NewParser().ParseUnverified(string(token), jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT token: %v", err)
	}
	claims := tk.Claims.(jwt.MapClaims)
	exp, ok := claims["exp"]
	if !ok {
		return nil, fmt.Errorf(`no "exp" found in claim`)
	}
	expireOn := time.Unix(int64(exp.(float64)), 0)
	if time.Now().After(expireOn) {
		return nil, fmt.Errorf("token has already expired")
	}

	return &AccessTokenAuthorizer{
		token: oauth2.Token{
			AccessToken: string(token),
			Expiry:      expireOn,
		},
	}, nil
}

var _ Authorizer = &AccessTokenAuthorizer{}

// AccessTokenAuthorizer is an Authorizer which supports the Azure CLI.
type AccessTokenAuthorizer struct {
	token oauth2.Token
}

// Token returns an access token using the Azure CLI as an authentication mechanism.
func (a *AccessTokenAuthorizer) Token(_ context.Context, _ *http.Request) (*oauth2.Token, error) {
	if time.Now().After(a.token.Expiry) {
		return nil, fmt.Errorf("token has already expired")
	}
	return &a.token, nil
}

// AuxiliaryTokens returns additional tokens for auxiliary tenant IDs, for use in multi-tenant scenarios
func (a *AccessTokenAuthorizer) AuxiliaryTokens(_ context.Context, _ *http.Request) ([]*oauth2.Token, error) {
	return nil, fmt.Errorf(" AuxiliaryTokens is not supported for AccessTokenAuthorizer")
}
