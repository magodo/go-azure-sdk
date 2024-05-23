package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySink = DelimitedTextSink{}

type DelimitedTextSink struct {
	FormatSettings *DelimitedTextWriteSettings `json:"formatSettings,omitempty"`
	StoreSettings  StoreWriteSettings          `json:"storeSettings"`

	// Fields inherited from CopySink
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SinkRetryCount           *interface{} `json:"sinkRetryCount,omitempty"`
	SinkRetryWait            *interface{} `json:"sinkRetryWait,omitempty"`
	WriteBatchSize           *interface{} `json:"writeBatchSize,omitempty"`
	WriteBatchTimeout        *interface{} `json:"writeBatchTimeout,omitempty"`
}

var _ json.Marshaler = DelimitedTextSink{}

func (s DelimitedTextSink) MarshalJSON() ([]byte, error) {
	type wrapper DelimitedTextSink
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling DelimitedTextSink: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling DelimitedTextSink: %+v", err)
	}
	decoded["type"] = "DelimitedTextSink"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling DelimitedTextSink: %+v", err)
	}

	return encoded, nil
}

var _ json.Unmarshaler = &DelimitedTextSink{}

func (s *DelimitedTextSink) UnmarshalJSON(bytes []byte) error {
	type alias DelimitedTextSink
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into DelimitedTextSink: %+v", err)
	}

	s.DisableMetricsCollection = decoded.DisableMetricsCollection
	s.FormatSettings = decoded.FormatSettings
	s.MaxConcurrentConnections = decoded.MaxConcurrentConnections
	s.SinkRetryCount = decoded.SinkRetryCount
	s.SinkRetryWait = decoded.SinkRetryWait
	s.WriteBatchSize = decoded.WriteBatchSize
	s.WriteBatchTimeout = decoded.WriteBatchTimeout

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling DelimitedTextSink into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["storeSettings"]; ok {
		impl, err := unmarshalStoreWriteSettingsImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'StoreSettings' for 'DelimitedTextSink': %+v", err)
		}
		s.StoreSettings = impl
	}
	return nil
}
