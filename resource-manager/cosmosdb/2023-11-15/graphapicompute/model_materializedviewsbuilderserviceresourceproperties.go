package graphapicompute

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/go-azure-helpers/lang/dates"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ ServiceResourceProperties = MaterializedViewsBuilderServiceResourceProperties{}

type MaterializedViewsBuilderServiceResourceProperties struct {
	Locations *[]RegionalServiceResource `json:"locations,omitempty"`

	// Fields inherited from ServiceResourceProperties
	CreationTime  *string        `json:"creationTime,omitempty"`
	InstanceCount *int64         `json:"instanceCount,omitempty"`
	InstanceSize  *ServiceSize   `json:"instanceSize,omitempty"`
	Status        *ServiceStatus `json:"status,omitempty"`
}

func (o *MaterializedViewsBuilderServiceResourceProperties) GetCreationTimeAsTime() (*time.Time, error) {
	if o.CreationTime == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.CreationTime, "2006-01-02T15:04:05Z07:00")
}

func (o *MaterializedViewsBuilderServiceResourceProperties) SetCreationTimeAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.CreationTime = &formatted
}

var _ json.Marshaler = MaterializedViewsBuilderServiceResourceProperties{}

func (s MaterializedViewsBuilderServiceResourceProperties) MarshalJSON() ([]byte, error) {
	type wrapper MaterializedViewsBuilderServiceResourceProperties
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling MaterializedViewsBuilderServiceResourceProperties: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling MaterializedViewsBuilderServiceResourceProperties: %+v", err)
	}
	decoded["serviceType"] = "MaterializedViewsBuilder"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling MaterializedViewsBuilderServiceResourceProperties: %+v", err)
	}

	return encoded, nil
}
