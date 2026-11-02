// Copyright (c) HashiCorp Inc. All rights reserved.
// Licensed under the MPL-2.0 License. See NOTICE.txt in the project root for license information.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"golang.org/x/oauth2"
)

type ManagedIdentityOIDCAuthorizerOptions struct {
	// Environment is the Azure environment/cloud being targeted.
	Environment environments.Environment

	// Api describes the Azure API being used.
	Api environments.Api

	// TenantId is the tenant to authenticate against.
	TenantId string

	// AuxiliaryTenantIds lists additional tenants to authenticate against.
	AuxiliaryTenantIds []string

	// AppClientId is the client ID of the application with the federated identity credential.
	AppClientId string

	// ManagedIdentityClientId is the client ID of the user-assigned managed identity trusted by the application.
	ManagedIdentityClientId string
}

// NewManagedIdentityOIDCAuthorizer returns an authorizer which uses a managed identity token
// as a client assertion to authenticate an application with Azure Identity.
func NewManagedIdentityOIDCAuthorizer(_ context.Context, options ManagedIdentityOIDCAuthorizerOptions) (Authorizer, error) {
	if strings.TrimSpace(options.TenantId) == "" {
		return nil, fmt.Errorf("TenantId must be specified")
	}
	if strings.TrimSpace(options.AppClientId) == "" {
		return nil, fmt.Errorf("AppClientId must be specified")
	}
	if strings.TrimSpace(options.ManagedIdentityClientId) == "" {
		return nil, fmt.Errorf("ManagedIdentityClientId must be specified")
	}
	if options.Environment.Authorization == nil || strings.TrimSpace(options.Environment.Authorization.LoginEndpoint) == "" {
		return nil, fmt.Errorf("no authorization login endpoint was found for this environment")
	}
	if options.Api == nil {
		return nil, fmt.Errorf("Api must be specified")
	}
	scope, err := environments.Scope(options.Api)
	if err != nil {
		return nil, fmt.Errorf("determining scope for %q: %w", options.Api.Name(), err)
	}

	assertionScope := "api://AzureADTokenExchange/.default"
	switch options.Environment.Name {
	case environments.AzureUSGovernmentCloud, "USGovernmentL5":
		assertionScope = "api://AzureADTokenExchangeUSGov/.default"
	case environments.AzureChinaCloud:
		assertionScope = "api://AzureADTokenExchangeChina/.default"
	}

	managedIdentityCredential, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(options.ManagedIdentityClientId),
		ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{
				ActiveDirectoryAuthorityHost: options.Environment.Authorization.LoginEndpoint,
			},
			Transport: MetadataClient,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("building managed identity credential: %w", err)
	}
	getAssertion := func(ctx context.Context) (string, error) {
		token, err := managedIdentityCredential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{assertionScope}})
		if err != nil {
			return "", fmt.Errorf("acquiring managed identity assertion: %w", err)
		}
		return token.Token, nil
	}

	auxiliaryTenantIds := append([]string(nil), options.AuxiliaryTenantIds...)
	credentialOptions := &azidentity.ClientAssertionCredentialOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{
				ActiveDirectoryAuthorityHost: options.Environment.Authorization.LoginEndpoint,
			},
			Transport: Client,
		},
		AdditionallyAllowedTenants: auxiliaryTenantIds,
	}
	authorizer := &ManagedIdentityOIDCAuthorizer{
		newCredential: func() (*azidentity.ClientAssertionCredential, error) {
			return azidentity.NewClientAssertionCredential(options.TenantId, options.AppClientId, getAssertion, credentialOptions)
		},
		scopes:             []string{*scope},
		auxiliaryTenantIds: auxiliaryTenantIds,
	}
	if err := authorizer.InvalidateCachedTokens(); err != nil {
		return nil, err
	}
	return authorizer, nil
}

var _ CachingAuthorizer = &ManagedIdentityOIDCAuthorizer{}

// ManagedIdentityOIDCAuthorizer authenticates an application using a federated managed identity.
type ManagedIdentityOIDCAuthorizer struct {
	mutex              sync.RWMutex
	credential         *azidentity.ClientAssertionCredential
	newCredential      func() (*azidentity.ClientAssertionCredential, error)
	scopes             []string
	auxiliaryTenantIds []string
}

func (a *ManagedIdentityOIDCAuthorizer) token(ctx context.Context, tenantId string) (*oauth2.Token, error) {
	if a.credential == nil {
		return nil, fmt.Errorf("ManagedIdentityOIDCAuthorizer is not configured")
	}

	result, err := a.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes:   a.scopes,
		TenantID: tenantId,
	})
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("ManagedIdentityOIDCAuthorizer: acquiring application token: %w", err)
	}
	return &oauth2.Token{
		AccessToken: result.Token,
		TokenType:   "Bearer",
		Expiry:      result.ExpiresOn,
	}, nil
}

// Token returns an access token for the application and configured API.
func (a *ManagedIdentityOIDCAuthorizer) Token(ctx context.Context, _ *http.Request) (*oauth2.Token, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.token(ctx, "")
}

// AuxiliaryTokens returns application tokens for the configured auxiliary tenants.
func (a *ManagedIdentityOIDCAuthorizer) AuxiliaryTokens(ctx context.Context, _ *http.Request) ([]*oauth2.Token, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	tokens := make([]*oauth2.Token, 0, len(a.auxiliaryTenantIds))
	for _, tenantId := range a.auxiliaryTenantIds {
		token, err := a.token(ctx, tenantId)
		if err != nil {
			return tokens, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

// InvalidateCachedTokens replaces the application credential to clear its token cache.
func (a *ManagedIdentityOIDCAuthorizer) InvalidateCachedTokens() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.newCredential == nil {
		return fmt.Errorf("ManagedIdentityOIDCAuthorizer is not configured")
	}
	credential, err := a.newCredential()
	if err != nil {
		return fmt.Errorf("building client assertion credential: %w", err)
	}
	a.credential = credential
	return nil
}
