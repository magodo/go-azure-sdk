package inferencegroup

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SkuCapacity struct {
	Default   *int64        `json:"default,omitempty"`
	Maximum   *int64        `json:"maximum,omitempty"`
	Minimum   *int64        `json:"minimum,omitempty"`
	ScaleType *SkuScaleType `json:"scaleType,omitempty"`
}
