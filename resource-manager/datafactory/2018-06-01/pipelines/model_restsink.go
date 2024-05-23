package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySink = RestSink{}

type RestSink struct {
	AdditionalHeaders   *interface{} `json:"additionalHeaders,omitempty"`
	HTTPCompressionType *interface{} `json:"httpCompressionType,omitempty"`
	HTTPRequestTimeout  *interface{} `json:"httpRequestTimeout,omitempty"`
	RequestInterval     *interface{} `json:"requestInterval,omitempty"`
	RequestMethod       *interface{} `json:"requestMethod,omitempty"`

	// Fields inherited from CopySink
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SinkRetryCount           *interface{} `json:"sinkRetryCount,omitempty"`
	SinkRetryWait            *interface{} `json:"sinkRetryWait,omitempty"`
	WriteBatchSize           *interface{} `json:"writeBatchSize,omitempty"`
	WriteBatchTimeout        *interface{} `json:"writeBatchTimeout,omitempty"`
}

var _ json.Marshaler = RestSink{}

func (s RestSink) MarshalJSON() ([]byte, error) {
	type wrapper RestSink
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling RestSink: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling RestSink: %+v", err)
	}
	decoded["type"] = "RestSink"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling RestSink: %+v", err)
	}

	return encoded, nil
}
