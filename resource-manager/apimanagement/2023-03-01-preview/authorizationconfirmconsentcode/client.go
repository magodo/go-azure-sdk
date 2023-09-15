package authorizationconfirmconsentcode

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	sdkEnv "github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AuthorizationConfirmConsentCodeClient struct {
	Client *resourcemanager.Client
}

func NewAuthorizationConfirmConsentCodeClientWithBaseURI(sdkApi sdkEnv.Api) (*AuthorizationConfirmConsentCodeClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(sdkApi, "authorizationconfirmconsentcode", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating AuthorizationConfirmConsentCodeClient: %+v", err)
	}

	return &AuthorizationConfirmConsentCodeClient{
		Client: client,
	}, nil
}
