package reservationsummaries

import (
	"time"

	"github.com/hashicorp/go-azure-helpers/lang/dates"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ReservationSummaryProperties struct {
	AvgUtilizationPercentage *float64 `json:"avgUtilizationPercentage,omitempty"`
	Kind                     *string  `json:"kind,omitempty"`
	MaxUtilizationPercentage *float64 `json:"maxUtilizationPercentage,omitempty"`
	MinUtilizationPercentage *float64 `json:"minUtilizationPercentage,omitempty"`
	PurchasedQuantity        *float64 `json:"purchasedQuantity,omitempty"`
	RemainingQuantity        *float64 `json:"remainingQuantity,omitempty"`
	ReservationId            *string  `json:"reservationId,omitempty"`
	ReservationOrderId       *string  `json:"reservationOrderId,omitempty"`
	ReservedHours            *float64 `json:"reservedHours,omitempty"`
	SkuName                  *string  `json:"skuName,omitempty"`
	TotalReservedQuantity    *float64 `json:"totalReservedQuantity,omitempty"`
	UsageDate                *string  `json:"usageDate,omitempty"`
	UsedHours                *float64 `json:"usedHours,omitempty"`
	UsedQuantity             *float64 `json:"usedQuantity,omitempty"`
	UtilizedPercentage       *float64 `json:"utilizedPercentage,omitempty"`
}

func (o *ReservationSummaryProperties) GetUsageDateAsTime() (*time.Time, error) {
	if o.UsageDate == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.UsageDate, "2006-01-02T15:04:05Z07:00")
}

func (o *ReservationSummaryProperties) SetUsageDateAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.UsageDate = &formatted
}
