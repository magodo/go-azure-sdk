package networkclouds

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type StorageApplianceSkuSlot struct {
	Properties *StorageApplianceSkuProperties `json:"properties,omitempty"`
	RackSlot   *int64                         `json:"rackSlot,omitempty"`
}
