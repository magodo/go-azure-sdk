package servicetasks

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ ProjectTaskProperties = UploadOCIDriverTaskProperties{}

type UploadOCIDriverTaskProperties struct {
	Input  *UploadOCIDriverTaskInput    `json:"input,omitempty"`
	Output *[]UploadOCIDriverTaskOutput `json:"output,omitempty"`

	// Fields inherited from ProjectTaskProperties
	ClientData *map[string]string   `json:"clientData,omitempty"`
	Commands   *[]CommandProperties `json:"commands,omitempty"`
	Errors     *[]ODataError        `json:"errors,omitempty"`
	State      *TaskState           `json:"state,omitempty"`
}

var _ json.Marshaler = UploadOCIDriverTaskProperties{}

func (s UploadOCIDriverTaskProperties) MarshalJSON() ([]byte, error) {
	type wrapper UploadOCIDriverTaskProperties
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling UploadOCIDriverTaskProperties: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling UploadOCIDriverTaskProperties: %+v", err)
	}
	decoded["taskType"] = "Service.Upload.OCI"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling UploadOCIDriverTaskProperties: %+v", err)
	}

	return encoded, nil
}
