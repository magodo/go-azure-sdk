package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/internal/test"
	"golang.org/x/oauth2"
)

func TestCustomCommandAuthorizer(t *testing.T) {
	ctx := context.Background()
	cmds := [][]string{
		{"az", "account", "get-access-token", "--resource={{.Endpoint}}"},
		{"echo", "mytoken"},
	}
	for _, cmd := range cmds {
		testCustomCommandAuthorizer(ctx, t, cmd)
	}
}

func testCustomCommandAuthorizer(ctx context.Context, t *testing.T, cmd []string) *oauth2.Token {
	test.AccTest(t)

	env, err := environments.FromName(test.Environment)
	if err != nil {
		t.Fatal(err)
	}

	opts := auth.CustomCommandAuthorizerOptions{
		Api:          env.MicrosoftGraph,
		TenantId:     test.TenantId,
		AuxTenantIds: []string{},
		TokenType:    "",
		Command:      cmd,
	}
	authorizer, err := auth.NewCustomCommandAuthorizer(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authorizer.Token(ctx, nil)
	if err != nil {
		t.Fatalf("auth.Token(): %v", err)
	}
	if token == nil {
		t.Fatalf("token was nil")
	}
	if token.AccessToken == "" {
		t.Fatalf("token.AccessToken was empty")
	}
	return token
}
