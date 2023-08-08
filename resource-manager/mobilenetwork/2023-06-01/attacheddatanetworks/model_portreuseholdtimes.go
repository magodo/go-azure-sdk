package attacheddatanetworks

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type PortReuseHoldTimes struct {
	Tcp *int64 `json:"tcp,omitempty"`
	Udp *int64 `json:"udp,omitempty"`
}
