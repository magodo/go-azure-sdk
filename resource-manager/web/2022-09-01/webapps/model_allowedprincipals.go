package webapps

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AllowedPrincipals struct {
	Groups     *[]string `json:"groups,omitempty"`
	Identities *[]string `json:"identities,omitempty"`
}
