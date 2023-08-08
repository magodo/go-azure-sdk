package dppfeaturesupport

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type FeatureValidationResponseBase interface {
}

func unmarshalFeatureValidationResponseBaseImplementation(input []byte) (FeatureValidationResponseBase, error) {
	if input == nil {
		return nil, nil
	}

	var temp map[string]interface{}
	if err := json.Unmarshal(input, &temp); err != nil {
		return nil, fmt.Errorf("unmarshaling FeatureValidationResponseBase into map[string]interface: %+v", err)
	}

	value, ok := temp["objectType"].(string)
	if !ok {
		return nil, nil
	}

	if strings.EqualFold(value, "FeatureValidationResponse") {
		var out FeatureValidationResponse
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into FeatureValidationResponse: %+v", err)
		}
		return out, nil
	}

	type RawFeatureValidationResponseBaseImpl struct {
		Type   string                 `json:"-"`
		Values map[string]interface{} `json:"-"`
	}
	out := RawFeatureValidationResponseBaseImpl{
		Type:   value,
		Values: temp,
	}
	return out, nil

}
