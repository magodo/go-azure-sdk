package v2023_03_01

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-azure-sdk/resource-manager/policyinsights/2023-03-01/checkpolicyrestrictions"
)

type Client struct {
	CheckPolicyRestrictions *checkpolicyrestrictions.CheckPolicyRestrictionsClient
}

func NewClientWithBaseURI(endpoint string, configureAuthFunc func(c *autorest.Client)) Client {

	checkPolicyRestrictionsClient := checkpolicyrestrictions.NewCheckPolicyRestrictionsClientWithBaseURI(endpoint)
	configureAuthFunc(&checkPolicyRestrictionsClient.Client)

	return Client{
		CheckPolicyRestrictions: &checkPolicyRestrictionsClient,
	}
}
