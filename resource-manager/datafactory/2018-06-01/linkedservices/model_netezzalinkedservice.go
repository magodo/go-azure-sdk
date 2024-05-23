package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ LinkedService = NetezzaLinkedService{}

type NetezzaLinkedService struct {
	TypeProperties NetezzaLinkedServiceTypeProperties `json:"typeProperties"`

	// Fields inherited from LinkedService
	Annotations *[]interface{}                     `json:"annotations,omitempty"`
	ConnectVia  *IntegrationRuntimeReference       `json:"connectVia,omitempty"`
	Description *string                            `json:"description,omitempty"`
	Parameters  *map[string]ParameterSpecification `json:"parameters,omitempty"`
}

var _ json.Marshaler = NetezzaLinkedService{}

func (s NetezzaLinkedService) MarshalJSON() ([]byte, error) {
	type wrapper NetezzaLinkedService
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling NetezzaLinkedService: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling NetezzaLinkedService: %+v", err)
	}
	decoded["type"] = "Netezza"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling NetezzaLinkedService: %+v", err)
	}

	return encoded, nil
}
