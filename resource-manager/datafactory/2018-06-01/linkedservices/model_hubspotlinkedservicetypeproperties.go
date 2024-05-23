package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type HubspotLinkedServiceTypeProperties struct {
	AccessToken           SecretBase   `json:"accessToken"`
	ClientId              interface{}  `json:"clientId"`
	ClientSecret          SecretBase   `json:"clientSecret"`
	EncryptedCredential   *string      `json:"encryptedCredential,omitempty"`
	RefreshToken          SecretBase   `json:"refreshToken"`
	UseEncryptedEndpoints *interface{} `json:"useEncryptedEndpoints,omitempty"`
	UseHostVerification   *interface{} `json:"useHostVerification,omitempty"`
	UsePeerVerification   *interface{} `json:"usePeerVerification,omitempty"`
}

var _ json.Unmarshaler = &HubspotLinkedServiceTypeProperties{}

func (s *HubspotLinkedServiceTypeProperties) UnmarshalJSON(bytes []byte) error {
	type alias HubspotLinkedServiceTypeProperties
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into HubspotLinkedServiceTypeProperties: %+v", err)
	}

	s.ClientId = decoded.ClientId
	s.EncryptedCredential = decoded.EncryptedCredential
	s.UseEncryptedEndpoints = decoded.UseEncryptedEndpoints
	s.UseHostVerification = decoded.UseHostVerification
	s.UsePeerVerification = decoded.UsePeerVerification

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling HubspotLinkedServiceTypeProperties into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["accessToken"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'AccessToken' for 'HubspotLinkedServiceTypeProperties': %+v", err)
		}
		s.AccessToken = impl
	}

	if v, ok := temp["clientSecret"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'ClientSecret' for 'HubspotLinkedServiceTypeProperties': %+v", err)
		}
		s.ClientSecret = impl
	}

	if v, ok := temp["refreshToken"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'RefreshToken' for 'HubspotLinkedServiceTypeProperties': %+v", err)
		}
		s.RefreshToken = impl
	}
	return nil
}
