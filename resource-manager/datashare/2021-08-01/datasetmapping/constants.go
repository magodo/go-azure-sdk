package datasetmapping

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type DataSetMappingKind string

const (
	DataSetMappingKindAdlsGenTwoFile               DataSetMappingKind = "AdlsGen2File"
	DataSetMappingKindAdlsGenTwoFileSystem         DataSetMappingKind = "AdlsGen2FileSystem"
	DataSetMappingKindAdlsGenTwoFolder             DataSetMappingKind = "AdlsGen2Folder"
	DataSetMappingKindBlob                         DataSetMappingKind = "Blob"
	DataSetMappingKindBlobFolder                   DataSetMappingKind = "BlobFolder"
	DataSetMappingKindContainer                    DataSetMappingKind = "Container"
	DataSetMappingKindKustoCluster                 DataSetMappingKind = "KustoCluster"
	DataSetMappingKindKustoDatabase                DataSetMappingKind = "KustoDatabase"
	DataSetMappingKindKustoTable                   DataSetMappingKind = "KustoTable"
	DataSetMappingKindSqlDBTable                   DataSetMappingKind = "SqlDBTable"
	DataSetMappingKindSqlDWTable                   DataSetMappingKind = "SqlDWTable"
	DataSetMappingKindSynapseWorkspaceSqlPoolTable DataSetMappingKind = "SynapseWorkspaceSqlPoolTable"
)

func PossibleValuesForDataSetMappingKind() []string {
	return []string{
		string(DataSetMappingKindAdlsGenTwoFile),
		string(DataSetMappingKindAdlsGenTwoFileSystem),
		string(DataSetMappingKindAdlsGenTwoFolder),
		string(DataSetMappingKindBlob),
		string(DataSetMappingKindBlobFolder),
		string(DataSetMappingKindContainer),
		string(DataSetMappingKindKustoCluster),
		string(DataSetMappingKindKustoDatabase),
		string(DataSetMappingKindKustoTable),
		string(DataSetMappingKindSqlDBTable),
		string(DataSetMappingKindSqlDWTable),
		string(DataSetMappingKindSynapseWorkspaceSqlPoolTable),
	}
}

func (s *DataSetMappingKind) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseDataSetMappingKind(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseDataSetMappingKind(input string) (*DataSetMappingKind, error) {
	vals := map[string]DataSetMappingKind{
		"adlsgen2file":                 DataSetMappingKindAdlsGenTwoFile,
		"adlsgen2filesystem":           DataSetMappingKindAdlsGenTwoFileSystem,
		"adlsgen2folder":               DataSetMappingKindAdlsGenTwoFolder,
		"blob":                         DataSetMappingKindBlob,
		"blobfolder":                   DataSetMappingKindBlobFolder,
		"container":                    DataSetMappingKindContainer,
		"kustocluster":                 DataSetMappingKindKustoCluster,
		"kustodatabase":                DataSetMappingKindKustoDatabase,
		"kustotable":                   DataSetMappingKindKustoTable,
		"sqldbtable":                   DataSetMappingKindSqlDBTable,
		"sqldwtable":                   DataSetMappingKindSqlDWTable,
		"synapseworkspacesqlpooltable": DataSetMappingKindSynapseWorkspaceSqlPoolTable,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := DataSetMappingKind(input)
	return &out, nil
}

type DataSetMappingStatus string

const (
	DataSetMappingStatusBroken DataSetMappingStatus = "Broken"
	DataSetMappingStatusOk     DataSetMappingStatus = "Ok"
)

func PossibleValuesForDataSetMappingStatus() []string {
	return []string{
		string(DataSetMappingStatusBroken),
		string(DataSetMappingStatusOk),
	}
}

func (s *DataSetMappingStatus) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseDataSetMappingStatus(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseDataSetMappingStatus(input string) (*DataSetMappingStatus, error) {
	vals := map[string]DataSetMappingStatus{
		"broken": DataSetMappingStatusBroken,
		"ok":     DataSetMappingStatusOk,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := DataSetMappingStatus(input)
	return &out, nil
}

type OutputType string

const (
	OutputTypeCsv     OutputType = "Csv"
	OutputTypeParquet OutputType = "Parquet"
)

func PossibleValuesForOutputType() []string {
	return []string{
		string(OutputTypeCsv),
		string(OutputTypeParquet),
	}
}

func (s *OutputType) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseOutputType(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseOutputType(input string) (*OutputType, error) {
	vals := map[string]OutputType{
		"csv":     OutputTypeCsv,
		"parquet": OutputTypeParquet,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := OutputType(input)
	return &out, nil
}

type ProvisioningState string

const (
	ProvisioningStateCreating  ProvisioningState = "Creating"
	ProvisioningStateDeleting  ProvisioningState = "Deleting"
	ProvisioningStateFailed    ProvisioningState = "Failed"
	ProvisioningStateMoving    ProvisioningState = "Moving"
	ProvisioningStateSucceeded ProvisioningState = "Succeeded"
)

func PossibleValuesForProvisioningState() []string {
	return []string{
		string(ProvisioningStateCreating),
		string(ProvisioningStateDeleting),
		string(ProvisioningStateFailed),
		string(ProvisioningStateMoving),
		string(ProvisioningStateSucceeded),
	}
}

func (s *ProvisioningState) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseProvisioningState(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseProvisioningState(input string) (*ProvisioningState, error) {
	vals := map[string]ProvisioningState{
		"creating":  ProvisioningStateCreating,
		"deleting":  ProvisioningStateDeleting,
		"failed":    ProvisioningStateFailed,
		"moving":    ProvisioningStateMoving,
		"succeeded": ProvisioningStateSucceeded,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ProvisioningState(input)
	return &out, nil
}
