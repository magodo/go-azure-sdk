package tagoperationlink

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	sdkEnv "github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type TagOperationLinkClient struct {
	Client *resourcemanager.Client
}

func NewTagOperationLinkClientWithBaseURI(sdkApi sdkEnv.Api) (*TagOperationLinkClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(sdkApi, "tagoperationlink", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating TagOperationLinkClient: %+v", err)
	}

	return &TagOperationLinkClient{
		Client: client,
	}, nil
}
