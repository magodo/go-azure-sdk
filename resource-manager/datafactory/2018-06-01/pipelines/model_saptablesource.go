package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = SapTableSource{}

type SapTableSource struct {
	AdditionalColumns                *interface{}               `json:"additionalColumns,omitempty"`
	BatchSize                        *interface{}               `json:"batchSize,omitempty"`
	CustomRfcReadTableFunctionModule *interface{}               `json:"customRfcReadTableFunctionModule,omitempty"`
	PartitionOption                  *interface{}               `json:"partitionOption,omitempty"`
	PartitionSettings                *SapTablePartitionSettings `json:"partitionSettings,omitempty"`
	QueryTimeout                     *interface{}               `json:"queryTimeout,omitempty"`
	RfcTableFields                   *interface{}               `json:"rfcTableFields,omitempty"`
	RfcTableOptions                  *interface{}               `json:"rfcTableOptions,omitempty"`
	RowCount                         *interface{}               `json:"rowCount,omitempty"`
	RowSkips                         *interface{}               `json:"rowSkips,omitempty"`
	SapDataColumnDelimiter           *interface{}               `json:"sapDataColumnDelimiter,omitempty"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = SapTableSource{}

func (s SapTableSource) MarshalJSON() ([]byte, error) {
	type wrapper SapTableSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SapTableSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SapTableSource: %+v", err)
	}
	decoded["type"] = "SapTableSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SapTableSource: %+v", err)
	}

	return encoded, nil
}
