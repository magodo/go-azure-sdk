package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = AzureDataExplorerSource{}

type AzureDataExplorerSource struct {
	AdditionalColumns *interface{} `json:"additionalColumns,omitempty"`
	NoTruncation      *interface{} `json:"noTruncation,omitempty"`
	Query             interface{}  `json:"query"`
	QueryTimeout      *interface{} `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = AzureDataExplorerSource{}

func (s AzureDataExplorerSource) MarshalJSON() ([]byte, error) {
	type wrapper AzureDataExplorerSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling AzureDataExplorerSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling AzureDataExplorerSource: %+v", err)
	}
	decoded["type"] = "AzureDataExplorerSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling AzureDataExplorerSource: %+v", err)
	}

	return encoded, nil
}
