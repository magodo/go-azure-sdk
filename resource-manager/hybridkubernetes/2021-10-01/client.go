package v2021_10_01

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-azure-sdk/resource-manager/hybridkubernetes/2021-10-01/connectedclusters"
)

type Client struct {
	ConnectedClusters *connectedclusters.ConnectedClustersClient
}

func NewClientWithBaseURI(endpoint string, configureAuthFunc func(c *autorest.Client)) Client {

	connectedClustersClient := connectedclusters.NewConnectedClustersClientWithBaseURI(endpoint)
	configureAuthFunc(&connectedClustersClient.Client)

	return Client{
		ConnectedClusters: &connectedClustersClient,
	}
}
