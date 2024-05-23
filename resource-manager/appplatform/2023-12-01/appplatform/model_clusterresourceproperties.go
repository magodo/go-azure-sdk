package appplatform

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ClusterResourceProperties struct {
	Fqdn                *string              `json:"fqdn,omitempty"`
	MarketplaceResource *MarketplaceResource `json:"marketplaceResource,omitempty"`
	NetworkProfile      *NetworkProfile      `json:"networkProfile,omitempty"`
	PowerState          *PowerState          `json:"powerState,omitempty"`
	ProvisioningState   *ProvisioningState   `json:"provisioningState,omitempty"`
	ServiceId           *string              `json:"serviceId,omitempty"`
	Version             *int64               `json:"version,omitempty"`
	VnetAddons          *ServiceVNetAddons   `json:"vnetAddons,omitempty"`
	ZoneRedundant       *bool                `json:"zoneRedundant,omitempty"`
}
