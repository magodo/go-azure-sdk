package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/internal/test"
	"golang.org/x/oauth2"
)

func TestAccAccessTokenAuthorizer(t *testing.T) {
	ctx := context.Background()
	testAccessTokenAuthorizer(ctx, t)
}

func testAccessTokenAuthorizer(ctx context.Context, t *testing.T) (token *oauth2.Token) {
	test.AccTest(t)

	env, err := environments.FromName(test.Environment)
	if err != nil {
		t.Fatal(err)
	}

	tk := jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": "RS256",
		},
		Claims: jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	}
	private, _ := rsa.GenerateKey(rand.Reader, 512)
	tkStr, _ := tk.SignedString(private)

	opts := auth.AccessTokenAuthorizerOptions{
		Api: env.MicrosoftGraph,
		TokenMap: map[string][]byte{
			"MicrosoftGraph": []byte(tkStr),
		},
	}
	authorizer, err := auth.NewAccessTokenAuthorizer(ctx, opts)
	if err != nil {
		t.Fatalf("NewAccessTokenAuthorizer(): %v", err)
	}
	if authorizer == nil {
		t.Fatal("authorizer is nil, expected Authorizer")
	}

	token, err = authorizer.Token(ctx, nil)
	if err != nil {
		t.Fatalf("authorizer.Token(): %v", err)
	}
	if token == nil {
		t.Fatalf("token was nil")
	}
	if token.AccessToken == "" {
		t.Fatalf("token.AccessToken was empty")
	}

	return
}
