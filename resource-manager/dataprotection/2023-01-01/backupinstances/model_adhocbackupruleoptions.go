package backupinstances

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AdHocBackupRuleOptions struct {
	RuleName      string                   `json:"ruleName"`
	TriggerOption AdhocBackupTriggerOption `json:"triggerOption"`
}
