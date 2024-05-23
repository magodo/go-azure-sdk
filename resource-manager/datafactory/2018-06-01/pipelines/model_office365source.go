package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = Office365Source{}

type Office365Source struct {
	AllowedGroups      *interface{} `json:"allowedGroups,omitempty"`
	DateFilterColumn   *interface{} `json:"dateFilterColumn,omitempty"`
	EndTime            *interface{} `json:"endTime,omitempty"`
	OutputColumns      *interface{} `json:"outputColumns,omitempty"`
	StartTime          *interface{} `json:"startTime,omitempty"`
	UserScopeFilterUri *interface{} `json:"userScopeFilterUri,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = Office365Source{}

func (s Office365Source) MarshalJSON() ([]byte, error) {
	type wrapper Office365Source
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling Office365Source: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling Office365Source: %+v", err)
	}
	decoded["type"] = "Office365Source"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling Office365Source: %+v", err)
	}

	return encoded, nil
}
