package tasks

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ ProjectTaskProperties = ConnectToTargetSqlSqlDbSyncTaskProperties{}

type ConnectToTargetSqlSqlDbSyncTaskProperties struct {
	Input  *ConnectToTargetSqlSqlDbSyncTaskInput `json:"input,omitempty"`
	Output *[]ConnectToTargetSqlDbTaskOutput     `json:"output,omitempty"`

	// Fields inherited from ProjectTaskProperties
	ClientData *map[string]string   `json:"clientData,omitempty"`
	Commands   *[]CommandProperties `json:"commands,omitempty"`
	Errors     *[]ODataError        `json:"errors,omitempty"`
	State      *TaskState           `json:"state,omitempty"`
}

var _ json.Marshaler = ConnectToTargetSqlSqlDbSyncTaskProperties{}

func (s ConnectToTargetSqlSqlDbSyncTaskProperties) MarshalJSON() ([]byte, error) {
	type wrapper ConnectToTargetSqlSqlDbSyncTaskProperties
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling ConnectToTargetSqlSqlDbSyncTaskProperties: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling ConnectToTargetSqlSqlDbSyncTaskProperties: %+v", err)
	}
	decoded["taskType"] = "ConnectToTarget.SqlDb.Sync"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling ConnectToTargetSqlSqlDbSyncTaskProperties: %+v", err)
	}

	return encoded, nil
}
