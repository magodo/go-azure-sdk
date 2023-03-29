package integrationruntimeobjectmetadata

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SsisObjectMetadataListResponse struct {
	NextLink *string               `json:"nextLink,omitempty"`
	Value    *[]SsisObjectMetadata `json:"value,omitempty"`
}
