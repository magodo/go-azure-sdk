package forecast

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ForecastComparisonExpression struct {
	Name     string               `json:"name"`
	Operator ForecastOperatorType `json:"operator"`
	Values   []string             `json:"values"`
}
