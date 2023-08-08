package diagnostics

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type KeyValuePairStringObject struct {
	Key   *string      `json:"key,omitempty"`
	Value *interface{} `json:"value,omitempty"`
}
