package tenants

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type CheckResourceNameResult struct {
	Name   *string             `json:"name,omitempty"`
	Status *ResourceNameStatus `json:"status,omitempty"`
	Type   *string             `json:"type,omitempty"`
}
