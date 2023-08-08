package usagedetails

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type GenerateDetailedCostReportMetricType string

const (
	GenerateDetailedCostReportMetricTypeActualCost    GenerateDetailedCostReportMetricType = "ActualCost"
	GenerateDetailedCostReportMetricTypeAmortizedCost GenerateDetailedCostReportMetricType = "AmortizedCost"
)

func PossibleValuesForGenerateDetailedCostReportMetricType() []string {
	return []string{
		string(GenerateDetailedCostReportMetricTypeActualCost),
		string(GenerateDetailedCostReportMetricTypeAmortizedCost),
	}
}

func (s *GenerateDetailedCostReportMetricType) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseGenerateDetailedCostReportMetricType(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseGenerateDetailedCostReportMetricType(input string) (*GenerateDetailedCostReportMetricType, error) {
	vals := map[string]GenerateDetailedCostReportMetricType{
		"actualcost":    GenerateDetailedCostReportMetricTypeActualCost,
		"amortizedcost": GenerateDetailedCostReportMetricTypeAmortizedCost,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := GenerateDetailedCostReportMetricType(input)
	return &out, nil
}
