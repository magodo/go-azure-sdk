package v2022_09_01

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-azure-sdk/resource-manager/policyinsights/2022-09-01/attestations"
)

type Client struct {
	Attestations *attestations.AttestationsClient
}

func NewClientWithBaseURI(endpoint string, configureAuthFunc func(c *autorest.Client)) Client {

	attestationsClient := attestations.NewAttestationsClientWithBaseURI(endpoint)
	configureAuthFunc(&attestationsClient.Client)

	return Client{
		Attestations: &attestationsClient,
	}
}
