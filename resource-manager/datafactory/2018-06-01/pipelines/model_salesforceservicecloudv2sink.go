package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySink = SalesforceServiceCloudV2Sink{}

type SalesforceServiceCloudV2Sink struct {
	ExternalIdFieldName *interface{}                   `json:"externalIdFieldName,omitempty"`
	IgnoreNullValues    *interface{}                   `json:"ignoreNullValues,omitempty"`
	WriteBehavior       *SalesforceV2SinkWriteBehavior `json:"writeBehavior,omitempty"`

	// Fields inherited from CopySink
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SinkRetryCount           *interface{} `json:"sinkRetryCount,omitempty"`
	SinkRetryWait            *interface{} `json:"sinkRetryWait,omitempty"`
	WriteBatchSize           *interface{} `json:"writeBatchSize,omitempty"`
	WriteBatchTimeout        *interface{} `json:"writeBatchTimeout,omitempty"`
}

var _ json.Marshaler = SalesforceServiceCloudV2Sink{}

func (s SalesforceServiceCloudV2Sink) MarshalJSON() ([]byte, error) {
	type wrapper SalesforceServiceCloudV2Sink
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SalesforceServiceCloudV2Sink: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SalesforceServiceCloudV2Sink: %+v", err)
	}
	decoded["type"] = "SalesforceServiceCloudV2Sink"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SalesforceServiceCloudV2Sink: %+v", err)
	}

	return encoded, nil
}
