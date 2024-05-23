package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySink = SqlDWSink{}

type SqlDWSink struct {
	AllowCopyCommand      *interface{}           `json:"allowCopyCommand,omitempty"`
	AllowPolyBase         *interface{}           `json:"allowPolyBase,omitempty"`
	CopyCommandSettings   *DWCopyCommandSettings `json:"copyCommandSettings,omitempty"`
	PolyBaseSettings      *PolybaseSettings      `json:"polyBaseSettings,omitempty"`
	PreCopyScript         *interface{}           `json:"preCopyScript,omitempty"`
	SqlWriterUseTableLock *interface{}           `json:"sqlWriterUseTableLock,omitempty"`
	TableOption           *interface{}           `json:"tableOption,omitempty"`
	UpsertSettings        *SqlDWUpsertSettings   `json:"upsertSettings,omitempty"`
	WriteBehavior         *interface{}           `json:"writeBehavior,omitempty"`

	// Fields inherited from CopySink
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SinkRetryCount           *interface{} `json:"sinkRetryCount,omitempty"`
	SinkRetryWait            *interface{} `json:"sinkRetryWait,omitempty"`
	WriteBatchSize           *interface{} `json:"writeBatchSize,omitempty"`
	WriteBatchTimeout        *interface{} `json:"writeBatchTimeout,omitempty"`
}

var _ json.Marshaler = SqlDWSink{}

func (s SqlDWSink) MarshalJSON() ([]byte, error) {
	type wrapper SqlDWSink
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling SqlDWSink: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling SqlDWSink: %+v", err)
	}
	decoded["type"] = "SqlDWSink"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling SqlDWSink: %+v", err)
	}

	return encoded, nil
}
