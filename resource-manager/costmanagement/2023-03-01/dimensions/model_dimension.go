package dimensions

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type Dimension struct {
	ETag       *string              `json:"eTag,omitempty"`
	Id         *string              `json:"id,omitempty"`
	Location   *string              `json:"location,omitempty"`
	Name       *string              `json:"name,omitempty"`
	Properties *DimensionProperties `json:"properties,omitempty"`
	Sku        *string              `json:"sku,omitempty"`
	Tags       *map[string]string   `json:"tags,omitempty"`
	Type       *string              `json:"type,omitempty"`
}
