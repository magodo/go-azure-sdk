package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ StoreWriteSettings = AzureBlobFSWriteSettings{}

type AzureBlobFSWriteSettings struct {
	BlockSizeInMB *interface{} `json:"blockSizeInMB,omitempty"`

	// Fields inherited from StoreWriteSettings
	CopyBehavior             *interface{}    `json:"copyBehavior,omitempty"`
	DisableMetricsCollection *interface{}    `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{}    `json:"maxConcurrentConnections,omitempty"`
	Metadata                 *[]MetadataItem `json:"metadata,omitempty"`
}

var _ json.Marshaler = AzureBlobFSWriteSettings{}

func (s AzureBlobFSWriteSettings) MarshalJSON() ([]byte, error) {
	type wrapper AzureBlobFSWriteSettings
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling AzureBlobFSWriteSettings: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling AzureBlobFSWriteSettings: %+v", err)
	}
	decoded["type"] = "AzureBlobFSWriteSettings"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling AzureBlobFSWriteSettings: %+v", err)
	}

	return encoded, nil
}
