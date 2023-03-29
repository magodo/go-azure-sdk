package vaultcertificates

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type RawCertificateData struct {
	AuthType    *AuthType `json:"authType,omitempty"`
	Certificate *string   `json:"certificate,omitempty"`
}
