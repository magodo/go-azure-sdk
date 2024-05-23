package dataconnectors

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type DataConnectorKind string

const (
	DataConnectorKindAmazonWebServicesCloudTrail               DataConnectorKind = "AmazonWebServicesCloudTrail"
	DataConnectorKindAzureActiveDirectory                      DataConnectorKind = "AzureActiveDirectory"
	DataConnectorKindAzureAdvancedThreatProtection             DataConnectorKind = "AzureAdvancedThreatProtection"
	DataConnectorKindAzureSecurityCenter                       DataConnectorKind = "AzureSecurityCenter"
	DataConnectorKindMicrosoftCloudAppSecurity                 DataConnectorKind = "MicrosoftCloudAppSecurity"
	DataConnectorKindMicrosoftDefenderAdvancedThreatProtection DataConnectorKind = "MicrosoftDefenderAdvancedThreatProtection"
	DataConnectorKindOfficeThreeSixFive                        DataConnectorKind = "Office365"
	DataConnectorKindThreatIntelligence                        DataConnectorKind = "ThreatIntelligence"
)

func PossibleValuesForDataConnectorKind() []string {
	return []string{
		string(DataConnectorKindAmazonWebServicesCloudTrail),
		string(DataConnectorKindAzureActiveDirectory),
		string(DataConnectorKindAzureAdvancedThreatProtection),
		string(DataConnectorKindAzureSecurityCenter),
		string(DataConnectorKindMicrosoftCloudAppSecurity),
		string(DataConnectorKindMicrosoftDefenderAdvancedThreatProtection),
		string(DataConnectorKindOfficeThreeSixFive),
		string(DataConnectorKindThreatIntelligence),
	}
}

func (s *DataConnectorKind) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseDataConnectorKind(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseDataConnectorKind(input string) (*DataConnectorKind, error) {
	vals := map[string]DataConnectorKind{
		"amazonwebservicescloudtrail":               DataConnectorKindAmazonWebServicesCloudTrail,
		"azureactivedirectory":                      DataConnectorKindAzureActiveDirectory,
		"azureadvancedthreatprotection":             DataConnectorKindAzureAdvancedThreatProtection,
		"azuresecuritycenter":                       DataConnectorKindAzureSecurityCenter,
		"microsoftcloudappsecurity":                 DataConnectorKindMicrosoftCloudAppSecurity,
		"microsoftdefenderadvancedthreatprotection": DataConnectorKindMicrosoftDefenderAdvancedThreatProtection,
		"office365":          DataConnectorKindOfficeThreeSixFive,
		"threatintelligence": DataConnectorKindThreatIntelligence,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := DataConnectorKind(input)
	return &out, nil
}

type DataTypeState string

const (
	DataTypeStateDisabled DataTypeState = "Disabled"
	DataTypeStateEnabled  DataTypeState = "Enabled"
)

func PossibleValuesForDataTypeState() []string {
	return []string{
		string(DataTypeStateDisabled),
		string(DataTypeStateEnabled),
	}
}

func (s *DataTypeState) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseDataTypeState(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseDataTypeState(input string) (*DataTypeState, error) {
	vals := map[string]DataTypeState{
		"disabled": DataTypeStateDisabled,
		"enabled":  DataTypeStateEnabled,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := DataTypeState(input)
	return &out, nil
}
