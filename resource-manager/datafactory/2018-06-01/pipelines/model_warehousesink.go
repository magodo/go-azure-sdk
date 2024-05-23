package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySink = WarehouseSink{}

type WarehouseSink struct {
	AllowCopyCommand    *interface{}           `json:"allowCopyCommand,omitempty"`
	CopyCommandSettings *DWCopyCommandSettings `json:"copyCommandSettings,omitempty"`
	PreCopyScript       *interface{}           `json:"preCopyScript,omitempty"`
	TableOption         *interface{}           `json:"tableOption,omitempty"`
	WriteBehavior       *interface{}           `json:"writeBehavior,omitempty"`

	// Fields inherited from CopySink
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SinkRetryCount           *interface{} `json:"sinkRetryCount,omitempty"`
	SinkRetryWait            *interface{} `json:"sinkRetryWait,omitempty"`
	WriteBatchSize           *interface{} `json:"writeBatchSize,omitempty"`
	WriteBatchTimeout        *interface{} `json:"writeBatchTimeout,omitempty"`
}

var _ json.Marshaler = WarehouseSink{}

func (s WarehouseSink) MarshalJSON() ([]byte, error) {
	type wrapper WarehouseSink
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling WarehouseSink: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling WarehouseSink: %+v", err)
	}
	decoded["type"] = "WarehouseSink"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling WarehouseSink: %+v", err)
	}

	return encoded, nil
}
