package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = OdbcSource{}

type OdbcSource struct {
	AdditionalColumns *interface{} `json:"additionalColumns,omitempty"`
	Query             *interface{} `json:"query,omitempty"`
	QueryTimeout      *interface{} `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = OdbcSource{}

func (s OdbcSource) MarshalJSON() ([]byte, error) {
	type wrapper OdbcSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling OdbcSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling OdbcSource: %+v", err)
	}
	decoded["type"] = "OdbcSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling OdbcSource: %+v", err)
	}

	return encoded, nil
}
