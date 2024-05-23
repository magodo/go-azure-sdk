package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = ServiceNowV2Source{}

type ServiceNowV2Source struct {
	AdditionalColumns *interface{}  `json:"additionalColumns,omitempty"`
	Expression        *ExpressionV2 `json:"expression,omitempty"`
	QueryTimeout      *interface{}  `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = ServiceNowV2Source{}

func (s ServiceNowV2Source) MarshalJSON() ([]byte, error) {
	type wrapper ServiceNowV2Source
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling ServiceNowV2Source: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling ServiceNowV2Source: %+v", err)
	}
	decoded["type"] = "ServiceNowV2Source"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling ServiceNowV2Source: %+v", err)
	}

	return encoded, nil
}
