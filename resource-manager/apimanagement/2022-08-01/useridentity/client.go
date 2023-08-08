package useridentity

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	sdkEnv "github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type UserIdentityClient struct {
	Client *resourcemanager.Client
}

func NewUserIdentityClientWithBaseURI(sdkApi sdkEnv.Api) (*UserIdentityClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(sdkApi, "useridentity", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating UserIdentityClient: %+v", err)
	}

	return &UserIdentityClient{
		Client: client,
	}, nil
}
