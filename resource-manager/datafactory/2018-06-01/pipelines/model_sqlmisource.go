package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = SqlMISource{}

type SqlMISource struct {
	AdditionalColumns            *interface{}          `json:"additionalColumns,omitempty"`
	IsolationLevel               *interface{}          `json:"isolationLevel,omitempty"`
	PartitionOption              *interface{}          `json:"partitionOption,omitempty"`
	PartitionSettings            *SqlPartitionSettings `json:"partitionSettings,omitempty"`
	ProduceAdditionalTypes       *interface{}          `json:"produceAdditionalTypes,omitempty"`
	QueryTimeout                 *interface{}          `json:"queryTimeout,omitempty"`
	SqlReaderQuery               *interface{}          `json:"sqlReaderQuery,omitempty"`
	SqlReaderStoredProcedureName *interface{}          `json:"sqlReaderStoredProcedureName,omitempty"`
	StoredProcedureParameters    *interface{}          `json:"storedProcedureParameters,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = SqlMISource{}

func (s SqlMISource) MarshalJSON() ([]byte, error) {
	type wrapper SqlMISource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SqlMISource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SqlMISource: %+v", err)
	}
	decoded["type"] = "SqlMISource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SqlMISource: %+v", err)
	}

	return encoded, nil
}
