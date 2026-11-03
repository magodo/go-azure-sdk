// Copyright (c) HashiCorp Inc. All rights reserved.
// Licensed under the MPL-2.0 License. See NOTICE.txt in the project root for license information.

package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/internal/test"
)

func TestManagedIdentityOIDCAuthorizer(t *testing.T) {
	ctx := context.Background()
	env := environments.AzurePublic()

	client, metadataClient := auth.Client, auth.MetadataClient
	t.Cleanup(func() { auth.Client, auth.MetadataClient = client, metadataClient })
	mock := &test.AzureADAccessTokenMockClient{
		Authorization: *env.Authorization,
	}
	auth.Client, auth.MetadataClient = mock, mock

	opts := auth.ManagedIdentityOIDCAuthorizerOptions{
		Environment:             *env,
		Api:                     env.MicrosoftGraph,
		TenantId:                "00000000-1111-0000-0000-000000000000",
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
