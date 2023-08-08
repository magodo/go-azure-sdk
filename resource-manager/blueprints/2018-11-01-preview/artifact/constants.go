package artifact

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ArtifactKind string

const (
	ArtifactKindPolicyAssignment ArtifactKind = "policyAssignment"
	ArtifactKindRoleAssignment   ArtifactKind = "roleAssignment"
	ArtifactKindTemplate         ArtifactKind = "template"
)

func PossibleValuesForArtifactKind() []string {
	return []string{
		string(ArtifactKindPolicyAssignment),
		string(ArtifactKindRoleAssignment),
		string(ArtifactKindTemplate),
	}
}

func (s *ArtifactKind) UnmarshalJSON(bytes []byte) error {
	var decoded string
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling: %+v", err)
	}
	out, err := parseArtifactKind(decoded)
	if err != nil {
		return fmt.Errorf("parsing %q: %+v", decoded, err)
	}
	*s = *out
	return nil
}

func parseArtifactKind(input string) (*ArtifactKind, error) {
	vals := map[string]ArtifactKind{
		"policyassignment": ArtifactKindPolicyAssignment,
		"roleassignment":   ArtifactKindRoleAssignment,
		"template":         ArtifactKindTemplate,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ArtifactKind(input)
	return &out, nil
}
