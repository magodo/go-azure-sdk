package blobinventorypolicies

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type BlobInventoryPolicyFilter struct {
	BlobTypes           *[]string `json:"blobTypes,omitempty"`
	IncludeBlobVersions *bool     `json:"includeBlobVersions,omitempty"`
	IncludeSnapshots    *bool     `json:"includeSnapshots,omitempty"`
	PrefixMatch         *[]string `json:"prefixMatch,omitempty"`
}