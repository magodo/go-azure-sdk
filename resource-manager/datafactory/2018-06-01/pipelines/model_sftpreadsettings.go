package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ StoreReadSettings = SftpReadSettings{}

type SftpReadSettings struct {
	DeleteFilesAfterCompletion *interface{} `json:"deleteFilesAfterCompletion,omitempty"`
	DisableChunking            *interface{} `json:"disableChunking,omitempty"`
	EnablePartitionDiscovery   *interface{} `json:"enablePartitionDiscovery,omitempty"`
	FileListPath               *interface{} `json:"fileListPath,omitempty"`
	ModifiedDatetimeEnd        *interface{} `json:"modifiedDatetimeEnd,omitempty"`
	ModifiedDatetimeStart      *interface{} `json:"modifiedDatetimeStart,omitempty"`
	PartitionRootPath          *interface{} `json:"partitionRootPath,omitempty"`
	Recursive                  *interface{} `json:"recursive,omitempty"`
	WildcardFileName           *interface{} `json:"wildcardFileName,omitempty"`
	WildcardFolderPath         *interface{} `json:"wildcardFolderPath,omitempty"`

	// Fields inherited from StoreReadSettings
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
}

var _ json.Marshaler = SftpReadSettings{}

func (s SftpReadSettings) MarshalJSON() ([]byte, error) {
	type wrapper SftpReadSettings
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SftpReadSettings: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SftpReadSettings: %+v", err)
	}
	decoded["type"] = "SftpReadSettings"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SftpReadSettings: %+v", err)
	}

	return encoded, nil
}
