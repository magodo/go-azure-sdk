package provider

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type GitHubActionWebAppStackSettings struct {
	IsSupported      *bool   `json:"isSupported,omitempty"`
	SupportedVersion *string `json:"supportedVersion,omitempty"`
}
