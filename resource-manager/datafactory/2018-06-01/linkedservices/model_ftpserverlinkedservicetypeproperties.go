package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type FtpServerLinkedServiceTypeProperties struct {
	AuthenticationType                *FtpAuthenticationType `json:"authenticationType,omitempty"`
	EnableServerCertificateValidation *interface{}           `json:"enableServerCertificateValidation,omitempty"`
	EnableSsl                         *interface{}           `json:"enableSsl,omitempty"`
	EncryptedCredential               *string                `json:"encryptedCredential,omitempty"`
	Host                              interface{}            `json:"host"`
	Password                          SecretBase             `json:"password"`
	Port                              *interface{}           `json:"port,omitempty"`
	UserName                          *interface{}           `json:"userName,omitempty"`
}

var _ json.Unmarshaler = &FtpServerLinkedServiceTypeProperties{}

func (s *FtpServerLinkedServiceTypeProperties) UnmarshalJSON(bytes []byte) error {
	type alias FtpServerLinkedServiceTypeProperties
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into FtpServerLinkedServiceTypeProperties: %+v", err)
	}

	s.AuthenticationType = decoded.AuthenticationType
	s.EnableServerCertificateValidation = decoded.EnableServerCertificateValidation
	s.EnableSsl = decoded.EnableSsl
	s.EncryptedCredential = decoded.EncryptedCredential
	s.Host = decoded.Host
	s.Port = decoded.Port
	s.UserName = decoded.UserName

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling FtpServerLinkedServiceTypeProperties into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["password"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'Password' for 'FtpServerLinkedServiceTypeProperties': %+v", err)
		}
		s.Password = impl
	}
	return nil
}
