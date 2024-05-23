package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ StoreWriteSettings = AzureFileStorageWriteSettings{}

type AzureFileStorageWriteSettings struct {

	// Fields inherited from StoreWriteSettings
	CopyBehavior             *interface{}    `json:"copyBehavior,omitempty"`
	DisableMetricsCollection *interface{}    `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{}    `json:"maxConcurrentConnections,omitempty"`
	Metadata                 *[]MetadataItem `json:"metadata,omitempty"`
}

var _ json.Marshaler = AzureFileStorageWriteSettings{}

func (s AzureFileStorageWriteSettings) MarshalJSON() ([]byte, error) {
	type wrapper AzureFileStorageWriteSettings
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling AzureFileStorageWriteSettings: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling AzureFileStorageWriteSettings: %+v", err)
	}
	decoded["type"] = "AzureFileStorageWriteSettings"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling AzureFileStorageWriteSettings: %+v", err)
	}

	return encoded, nil
}
