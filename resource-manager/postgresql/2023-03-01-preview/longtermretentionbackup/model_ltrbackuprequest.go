package longtermretentionbackup

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type LtrBackupRequest struct {
	BackupSettings BackupSettings     `json:"backupSettings"`
	TargetDetails  BackupStoreDetails `json:"targetDetails"`
}
