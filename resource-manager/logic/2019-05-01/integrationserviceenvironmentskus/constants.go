package integrationserviceenvironmentskus

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type IntegrationServiceEnvironmentSkuName string

const (
	IntegrationServiceEnvironmentSkuNameDeveloper    IntegrationServiceEnvironmentSkuName = "Developer"
	IntegrationServiceEnvironmentSkuNameNotSpecified IntegrationServiceEnvironmentSkuName = "NotSpecified"
	IntegrationServiceEnvironmentSkuNamePremium      IntegrationServiceEnvironmentSkuName = "Premium"
)

func PossibleValuesForIntegrationServiceEnvironmentSkuName() []string {
	return []string{
		string(IntegrationServiceEnvironmentSkuNameDeveloper),
		string(IntegrationServiceEnvironmentSkuNameNotSpecified),
		string(IntegrationServiceEnvironmentSkuNamePremium),
	}
}

func (s *IntegrationServiceEnvironmentSkuName) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseIntegrationServiceEnvironmentSkuName(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseIntegrationServiceEnvironmentSkuName(input string) (*IntegrationServiceEnvironmentSkuName, error) {
	vals := map[string]IntegrationServiceEnvironmentSkuName{
		"developer":    IntegrationServiceEnvironmentSkuNameDeveloper,
		"notspecified": IntegrationServiceEnvironmentSkuNameNotSpecified,
		"premium":      IntegrationServiceEnvironmentSkuNamePremium,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := IntegrationServiceEnvironmentSkuName(input)
	return &out, nil
}

type IntegrationServiceEnvironmentSkuScaleType string

const (
	IntegrationServiceEnvironmentSkuScaleTypeAutomatic IntegrationServiceEnvironmentSkuScaleType = "Automatic"
	IntegrationServiceEnvironmentSkuScaleTypeManual    IntegrationServiceEnvironmentSkuScaleType = "Manual"
	IntegrationServiceEnvironmentSkuScaleTypeNone      IntegrationServiceEnvironmentSkuScaleType = "None"
)

func PossibleValuesForIntegrationServiceEnvironmentSkuScaleType() []string {
	return []string{
		string(IntegrationServiceEnvironmentSkuScaleTypeAutomatic),
		string(IntegrationServiceEnvironmentSkuScaleTypeManual),
		string(IntegrationServiceEnvironmentSkuScaleTypeNone),
	}
}

func (s *IntegrationServiceEnvironmentSkuScaleType) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseIntegrationServiceEnvironmentSkuScaleType(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseIntegrationServiceEnvironmentSkuScaleType(input string) (*IntegrationServiceEnvironmentSkuScaleType, error) {
	vals := map[string]IntegrationServiceEnvironmentSkuScaleType{
		"automatic": IntegrationServiceEnvironmentSkuScaleTypeAutomatic,
		"manual":    IntegrationServiceEnvironmentSkuScaleTypeManual,
		"none":      IntegrationServiceEnvironmentSkuScaleTypeNone,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := IntegrationServiceEnvironmentSkuScaleType(input)
	return &out, nil
}
