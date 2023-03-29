package v2022_12_12

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/go-azure-sdk/resource-manager/deviceprovisioningservices/2022-12-12/dpscertificate"
	"github.com/hashicorp/go-azure-sdk/resource-manager/deviceprovisioningservices/2022-12-12/iotdpsresource"
)

type Client struct {
	DpsCertificate *dpscertificate.DpsCertificateClient
	IotDpsResource *iotdpsresource.IotDpsResourceClient
}

func NewClientWithBaseURI(endpoint string, configureAuthFunc func(c *autorest.Client)) Client {

	dpsCertificateClient := dpscertificate.NewDpsCertificateClientWithBaseURI(endpoint)
	configureAuthFunc(&dpsCertificateClient.Client)

	iotDpsResourceClient := iotdpsresource.NewIotDpsResourceClientWithBaseURI(endpoint)
	configureAuthFunc(&iotDpsResourceClient.Client)

	return Client{
		DpsCertificate: &dpsCertificateClient,
		IotDpsResource: &iotDpsResourceClient,
	}
}
