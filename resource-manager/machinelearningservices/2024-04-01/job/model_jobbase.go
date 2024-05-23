package job

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type JobBase interface {
}

// RawJobBaseImpl is returned when the Discriminated Value
// doesn't match any of the defined types
// NOTE: this should only be used when a type isn't defined for this type of Object (as a workaround)
// and is used only for Deserialization (e.g. this cannot be used as a Request Payload).
type RawJobBaseImpl struct {
	Type   string
	Values map[string]interface{}
}

func unmarshalJobBaseImplementation(input []byte) (JobBase, error) {
	if input == nil {
		return nil, nil
	}

	var temp map[string]interface{}
	if err := json.Unmarshal(input, &temp); err != nil {
		return nil, fmt.Errorf("unmarshaling JobBase into map[string]interface: %+v", err)
	}

	value, ok := temp["jobType"].(string)
	if !ok {
		return nil, nil
	}

	if strings.EqualFold(value, "AutoML") {
		var out AutoMLJob
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into AutoMLJob: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "Command") {
		var out CommandJob
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into CommandJob: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "Pipeline") {
		var out PipelineJob
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into PipelineJob: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "Spark") {
		var out SparkJob
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into SparkJob: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "Sweep") {
		var out SweepJob
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into SweepJob: %+v", err)
		}
		return out, nil
	}

	out := RawJobBaseImpl{
		Type:   value,
		Values: temp,
	}
	return out, nil

}
