package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = DrillSource{}

type DrillSource struct {
	AdditionalColumns *interface{} `json:"additionalColumns,omitempty"`
	Query             *interface{} `json:"query,omitempty"`
	QueryTimeout      *interface{} `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = DrillSource{}

func (s DrillSource) MarshalJSON() ([]byte, error) {
	type wrapper DrillSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling DrillSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling DrillSource: %+v", err)
	}
	decoded["type"] = "DrillSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling DrillSource: %+v", err)
	}

	return encoded, nil
}
