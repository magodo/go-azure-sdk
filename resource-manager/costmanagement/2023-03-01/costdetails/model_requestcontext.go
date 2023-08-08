package costdetails

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type RequestContext struct {
	RequestBody  *GenerateCostDetailsReportRequestDefinition `json:"requestBody,omitempty"`
	RequestScope *string                                     `json:"requestScope,omitempty"`
}
