package experiments

import (
	"time"

	"github.com/hashicorp/go-azure-helpers/lang/dates"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ExperimentStatusProperties struct {
	CreatedDateUtc *string `json:"createdDateUtc,omitempty"`
	EndDateUtc     *string `json:"endDateUtc,omitempty"`
	Status         *string `json:"status,omitempty"`
}

func (o *ExperimentStatusProperties) GetCreatedDateUtcAsTime() (*time.Time, error) {
	if o.CreatedDateUtc == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.CreatedDateUtc, "2006-01-02T15:04:05Z07:00")
}

func (o *ExperimentStatusProperties) SetCreatedDateUtcAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.CreatedDateUtc = &formatted
}

func (o *ExperimentStatusProperties) GetEndDateUtcAsTime() (*time.Time, error) {
	if o.EndDateUtc == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.EndDateUtc, "2006-01-02T15:04:05Z07:00")
}

func (o *ExperimentStatusProperties) SetEndDateUtcAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.EndDateUtc = &formatted
}
