package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ StoreWriteSettings = SftpWriteSettings{}

type SftpWriteSettings struct {
	OperationTimeout  *interface{} `json:"operationTimeout,omitempty"`
	UseTempFileRename *interface{} `json:"useTempFileRename,omitempty"`

	// Fields inherited from StoreWriteSettings
	CopyBehavior             *interface{}    `json:"copyBehavior,omitempty"`
	DisableMetricsCollection *interface{}    `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{}    `json:"maxConcurrentConnections,omitempty"`
	Metadata                 *[]MetadataItem `json:"metadata,omitempty"`
}

var _ json.Marshaler = SftpWriteSettings{}

func (s SftpWriteSettings) MarshalJSON() ([]byte, error) {
	type wrapper SftpWriteSettings
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SftpWriteSettings: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SftpWriteSettings: %+v", err)
	}
	decoded["type"] = "SftpWriteSettings"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SftpWriteSettings: %+v", err)
	}

	return encoded, nil
}
