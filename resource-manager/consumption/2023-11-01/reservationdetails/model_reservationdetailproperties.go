package reservationdetails

import (
	"time"

	"github.com/hashicorp/go-azure-helpers/lang/dates"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ReservationDetailProperties struct {
	InstanceFlexibilityGroup *string  `json:"instanceFlexibilityGroup,omitempty"`
	InstanceFlexibilityRatio *string  `json:"instanceFlexibilityRatio,omitempty"`
	InstanceId               *string  `json:"instanceId,omitempty"`
	Kind                     *string  `json:"kind,omitempty"`
	ReservationId            *string  `json:"reservationId,omitempty"`
	ReservationOrderId       *string  `json:"reservationOrderId,omitempty"`
	ReservedHours            *float64 `json:"reservedHours,omitempty"`
	SkuName                  *string  `json:"skuName,omitempty"`
	TotalReservedQuantity    *float64 `json:"totalReservedQuantity,omitempty"`
	UsageDate                *string  `json:"usageDate,omitempty"`
	UsedHours                *float64 `json:"usedHours,omitempty"`
}

func (o *ReservationDetailProperties) GetUsageDateAsTime() (*time.Time, error) {
	if o.UsageDate == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.UsageDate, "2006-01-02T15:04:05Z07:00")
}

func (o *ReservationDetailProperties) SetUsageDateAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.UsageDate = &formatted
}
