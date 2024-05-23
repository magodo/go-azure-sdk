package pipelines

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ CopySource = OrcSource{}

type OrcSource struct {
	AdditionalColumns *interface{}      `json:"additionalColumns,omitempty"`
	StoreSettings     StoreReadSettings `json:"storeSettings"`

	// Fields inherited from CopySource
	DisableMetricsCollection *interface{} `json:"disableMetricsCollection,omitempty"`
	MaxConcurrentConnections *interface{} `json:"maxConcurrentConnections,omitempty"`
	SourceRetryCount         *interface{} `json:"sourceRetryCount,omitempty"`
	SourceRetryWait          *interface{} `json:"sourceRetryWait,omitempty"`
}

var _ json.Marshaler = OrcSource{}

func (s OrcSource) MarshalJSON() ([]byte, error) {
	type wrapper OrcSource
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling OrcSource: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling OrcSource: %+v", err)
	}
	decoded["type"] = "OrcSource"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling OrcSource: %+v", err)
	}

	return encoded, nil
}

var _ json.Unmarshaler = &OrcSource{}

func (s *OrcSource) UnmarshalJSON(bytes []byte) error {
	type alias OrcSource
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into OrcSource: %+v", err)
	}

	s.AdditionalColumns = decoded.AdditionalColumns
	s.DisableMetricsCollection = decoded.DisableMetricsCollection
	s.MaxConcurrentConnections = decoded.MaxConcurrentConnections
	s.SourceRetryCount = decoded.SourceRetryCount
	s.SourceRetryWait = decoded.SourceRetryWait

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling OrcSource into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["storeSettings"]; ok {
		impl, err := unmarshalStoreReadSettingsImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'StoreSettings' for 'OrcSource': %+v", err)
		}
		s.StoreSettings = impl
	}
	return nil
}
