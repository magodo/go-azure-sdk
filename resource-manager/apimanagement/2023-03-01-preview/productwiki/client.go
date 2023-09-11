package productwiki

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	sdkEnv "github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ProductWikiClient struct {
	Client *resourcemanager.Client
}

func NewProductWikiClientWithBaseURI(sdkApi sdkEnv.Api) (*ProductWikiClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(sdkApi, "productwiki", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating ProductWikiClient: %+v", err)
	}

	return &ProductWikiClient{
		Client: client,
	}, nil
}
