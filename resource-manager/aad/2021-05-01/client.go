package v2021_05_01

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-azure-sdk/resource-manager/aad/2021-05-01/domainservices"
	"github.com/hashicorp/go-azure-sdk/resource-manager/aad/2021-05-01/oucontainer"
)

type Client struct {
	DomainServices *domainservices.DomainServicesClient
	OuContainer    *oucontainer.OuContainerClient
}

func NewClientWithBaseURI(endpoint string, configureAuthFunc func(c *autorest.Client)) Client {

	domainServicesClient := domainservices.NewDomainServicesClientWithBaseURI(endpoint)
	configureAuthFunc(&domainServicesClient.Client)

	ouContainerClient := oucontainer.NewOuContainerClientWithBaseURI(endpoint)
	configureAuthFunc(&ouContainerClient.Client)

	return Client{
		DomainServices: &domainServicesClient,
		OuContainer:    &ouContainerClient,
	}
}
