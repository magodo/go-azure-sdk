package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = AzureTableSource{}

type AzureTableSource struct {
	AdditionalColumns                   *interface{} `json:"additionalColumns,omitempty"`
	AzureTableSourceIgnoreTableNotFound *interface{} `json:"azureTableSourceIgnoreTableNotFound,omitempty"`
	AzureTableSourceQuery               *interface{} `json:"azureTableSourceQuery,omitempty"`
	QueryTimeout                        *interface{} `json:"queryTimeout,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = AzureTableSource{}

func (s AzureTableSource) MarshalJSON() ([]byte, error) {
	type wrapper AzureTableSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling AzureTableSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling AzureTableSource: %+v", err)
	}
	decoded["type"] = "AzureTableSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling AzureTableSource: %+v", err)
	}

	return encoded, nil
}
