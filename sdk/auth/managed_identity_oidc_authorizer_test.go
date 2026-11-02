// Copyright (c) HashiCorp Inc. All rights reserved.
// Licensed under the MPL-2.0 License. See NOTICE.txt in the project root for license information.

package auth_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/internal/test"
)

func TestManagedIdentityOIDCAuthorizer(t *testing.T) {
	ctx := context.Background()
	env := environments.AzurePublic()

	t.Setenv(environments.AzureRegionalAuthorityName, "")
	for _, name := range []string{"IDENTITY_ENDPOINT", "IDENTITY_HEADER", "IDENTITY_SERVER_THUMBPRINT", "IMDS_ENDPOINT", "MSI_ENDPOINT", "MSI_SECRET"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}

	client, metadataClient := auth.Client, auth.MetadataClient
	t.Cleanup(func() { auth.Client, auth.MetadataClient = client, metadataClient })
	mock := &managedIdentityOIDCMockClient{
		AzureADAccessTokenMockClient: test.AzureADAccessTokenMockClient{
			Authorization: *env.Authorization,
		},
	}
	auth.Client, auth.MetadataClient = mock, mock

	opts := auth.ManagedIdentityOIDCAuthorizerOptions{
		Environment:             *env,
		Api:                     env.MicrosoftGraph,
		TenantId:                "00000000-1111-0000-0000-000000000000",
		AuxiliaryTenantIds:      test.AuxiliaryTenantIds,
		AppClientId:             "11111111-0000-0000-0000-000000000000",
		ManagedIdentityClientId: "22222222-0000-0000-0000-000000000000",
	}

	authorizer, err := auth.NewManagedIdentityOIDCAuthorizer(ctx, opts)
	if err != nil {
		t.Fatalf("NewManagedIdentityOIDCAuthorizer(): %v", err)
	}

	if authorizer == nil {
		t.Fatal("authorizer is nil, expected Authorizer")
	}

	if _, err = testObtainAccessToken(ctx, authorizer); err != nil {
		t.Fatal(err)
	}
}

type managedIdentityOIDCMockClient struct {
	test.AzureADAccessTokenMockClient
}

func (c *managedIdentityOIDCMockClient) Do(req *http.Request) (*http.Response, error) {
	var body string
	switch {
	case req.URL.Path == "/common/discovery/instance":
		endpoint, err := url.Parse(req.URL.Query().Get("authorization_endpoint"))
		if err != nil {
			return nil, err
		}
		authority := strings.TrimSuffix(endpoint.String(), "/oauth2/v2.0/authorize")
		body = fmt.Sprintf(`{"tenant_discovery_endpoint":%q,"metadata":[{"preferred_network":%q,"preferred_cache":%q,"aliases":[%q]}]}`,
			authority+"/v2.0/.well-known/openid-configuration", endpoint.Host, endpoint.Host, endpoint.Host)
	case strings.HasSuffix(req.URL.Path, "/v2.0/.well-known/openid-configuration"):
		authority := strings.TrimSuffix(req.URL.String(), "/v2.0/.well-known/openid-configuration")
		body = fmt.Sprintf(`{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`,
			authority+"/oauth2/v2.0/authorize", authority+"/oauth2/v2.0/token", authority+"/v2.0")
	default:
		return c.AzureADAccessTokenMockClient.Do(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}
