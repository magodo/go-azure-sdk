package availableskus

import (
	"github.com/hashicorp/go-azure-helpers/resourcemanager/zones"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SkuLocationInfo struct {
	Location *string       `json:"location,omitempty"`
	Sites    *[]string     `json:"sites,omitempty"`
	Zones    *zones.Schema `json:"zones,omitempty"`
}
