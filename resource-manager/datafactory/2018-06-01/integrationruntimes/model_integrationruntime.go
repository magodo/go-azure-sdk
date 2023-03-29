package integrationruntimes

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type IntegrationRuntime struct {
	Description *string                `json:"description,omitempty"`
	Type        IntegrationRuntimeType `json:"type"`
}
