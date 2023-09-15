package experiments

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type FilterType string

const (
	FilterTypeSimple FilterType = "Simple"
)

func PossibleValuesForFilterType() []string {
	return []string{
		string(FilterTypeSimple),
	}
}

func (s *FilterType) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseFilterType(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseFilterType(input string) (*FilterType, error) {
	vals := map[string]FilterType{
		"simple": FilterTypeSimple,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := FilterType(input)
	return &out, nil
}

type SelectorType string

const (
	SelectorTypeList  SelectorType = "List"
	SelectorTypeQuery SelectorType = "Query"
)

func PossibleValuesForSelectorType() []string {
	return []string{
		string(SelectorTypeList),
		string(SelectorTypeQuery),
	}
}

func (s *SelectorType) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseSelectorType(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseSelectorType(input string) (*SelectorType, error) {
	vals := map[string]SelectorType{
		"list":  SelectorTypeList,
		"query": SelectorTypeQuery,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := SelectorType(input)
	return &out, nil
}
