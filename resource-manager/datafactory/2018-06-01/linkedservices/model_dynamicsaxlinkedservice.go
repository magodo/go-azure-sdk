package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ LinkedService = DynamicsAXLinkedService{}

type DynamicsAXLinkedService struct {
	TypeProperties DynamicsAXLinkedServiceTypeProperties `json:"typeProperties"`

	// Fields inherited from LinkedService
	Annotations *[]interface{}                     `json:"annotations,omitempty"`
	ConnectVia  *IntegrationRuntimeReference       `json:"connectVia,omitempty"`
	Description *string                            `json:"description,omitempty"`
	Parameters  *map[string]ParameterSpecification `json:"parameters,omitempty"`
}

var _ json.Marshaler = DynamicsAXLinkedService{}

func (s DynamicsAXLinkedService) MarshalJSON() ([]byte, error) {
	type wrapper DynamicsAXLinkedService
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling DynamicsAXLinkedService: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling DynamicsAXLinkedService: %+v", err)
	}
	decoded["type"] = "DynamicsAX"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling DynamicsAXLinkedService: %+v", err)
	}

	return encoded, nil
}
