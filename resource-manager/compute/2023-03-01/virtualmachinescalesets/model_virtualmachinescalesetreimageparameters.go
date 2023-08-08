package virtualmachinescalesets

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type VirtualMachineScaleSetReimageParameters struct {
	ExactVersion *string                    `json:"exactVersion,omitempty"`
	InstanceIds  *[]string                  `json:"instanceIds,omitempty"`
	OsProfile    *OSProfileProvisioningData `json:"osProfile,omitempty"`
	TempDisk     *bool                      `json:"tempDisk,omitempty"`
}
