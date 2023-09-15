package costallocationrules

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type TargetCostAllocationResource struct {
	Name         string                     `json:"name"`
	PolicyType   CostAllocationPolicyType   `json:"policyType"`
	ResourceType CostAllocationResourceType `json:"resourceType"`
	Values       []CostAllocationProportion `json:"values"`
}
