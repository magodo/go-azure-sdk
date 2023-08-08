package prediction

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type PredictionRequestProperties struct {
	ExtendedProperties *interface{}    `json:"extendedProperties,omitempty"`
	PredictionType     *PredictionType `json:"predictionType,omitempty"`
}
