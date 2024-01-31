package tasks

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ ConnectionInfo = OracleConnectionInfo{}

type OracleConnectionInfo struct {
	DataSource string `json:"dataSource"`

	// Fields inherited from ConnectionInfo
	Password *string `json:"password,omitempty"`
	UserName *string `json:"userName,omitempty"`
}

var _ json.Marshaler = OracleConnectionInfo{}

func (s OracleConnectionInfo) MarshalJSON() ([]byte, error) {
	type wrapper OracleConnectionInfo
	wrapped := wrapper(s)
	encoded, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshaling OracleConnectionInfo: %+v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshaling OracleConnectionInfo: %+v", err)
	}
	decoded["type"] = "OracleConnectionInfo"

	encoded, err = json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling OracleConnectionInfo: %+v", err)
	}

	return encoded, nil
}
