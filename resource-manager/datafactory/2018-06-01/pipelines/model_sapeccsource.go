package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = SapEccSource{}

type SapEccSource struct {
	AdditionalColumns  *interface{} `json:"additionalColumns,omitempty"`
	HTTPRequestTimeout *interface{} `json:"httpRequestTimeout,omitempty"`
	Query              *interface{} `json:"query,omitempty"`
	QueryTimeout       *interface{} `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = SapEccSource{}

func (s SapEccSource) MarshalJSON() ([]byte, error) {
	type wrapper SapEccSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SapEccSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SapEccSource: %+v", err)
	}
	decoded["type"] = "SapEccSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SapEccSource: %+v", err)
	}

	return encoded, nil
}
