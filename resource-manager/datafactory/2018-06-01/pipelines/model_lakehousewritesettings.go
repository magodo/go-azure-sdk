package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ StoreWriteSettings = LakeHouseWriteSettings{}

type LakeHouseWriteSettings struct {

	// Fields inherited from StoreWriteSettings
	CopyBehavior             *interface{}    `json:"copyBehavior,omitempty"`
	DisableMetricsCollection *interface{}    `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{}    `json:"maxConcurrentConnections,omitempty"`
	Metadata                 *[]MetadataItem `json:"metadata,omitempty"`
}

var _ json.Marshaler = LakeHouseWriteSettings{}

func (s LakeHouseWriteSettings) MarshalJSON() ([]byte, error) {
	type wrapper LakeHouseWriteSettings
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling LakeHouseWriteSettings: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling LakeHouseWriteSettings: %+v", err)
	}
	decoded["type"] = "LakeHouseWriteSettings"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling LakeHouseWriteSettings: %+v", err)
	}

	return encoded, nil
}
