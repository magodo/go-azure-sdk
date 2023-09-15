package replicationjobs

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type TaskTypeDetails interface {
}

// RawModeOfTransitImpl is returned when the Discriminated Value
// doesn't match any of the defined types
// NOTE: this should only be used when a type isn't defined for this type of Object (as a workaround)
// and is used only for Deserialization (e.g. this cannot be used as a Request Payload).
type RawTaskTypeDetailsImpl struct {
	Type   string
	Values map[string]interface{}
}

func unmarshalTaskTypeDetailsImplementation(input []byte) (TaskTypeDetails, error) {
	if input == nil {
		return nil, nil
	}

	var temp map[string]interface{}
	if err := json.Unmarshal(input, &temp); err != nil {
		return nil, fmt.Errorf("unmarshaling TaskTypeDetails into map[string]interface: %+v", err)
	}

	value, ok := temp["instanceType"].(string)
	if !ok {
		return nil, nil
	}

	if strings.EqualFold(value, "AutomationRunbookTaskDetails") {
		var out AutomationRunbookTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into AutomationRunbookTaskDetails: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "ConsistencyCheckTaskDetails") {
		var out ConsistencyCheckTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into ConsistencyCheckTaskDetails: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "JobTaskDetails") {
		var out JobTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into JobTaskDetails: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "ManualActionTaskDetails") {
		var out ManualActionTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into ManualActionTaskDetails: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "ScriptActionTaskDetails") {
		var out ScriptActionTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into ScriptActionTaskDetails: %+v", err)
		}
		return out, nil
	}

	if strings.EqualFold(value, "VmNicUpdatesTaskDetails") {
		var out VMNicUpdatesTaskDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into VMNicUpdatesTaskDetails: %+v", err)
		}
		return out, nil
	}

	out := RawTaskTypeDetailsImpl{
		Type:   value,
		Values: temp,
	}
	return out, nil

}
