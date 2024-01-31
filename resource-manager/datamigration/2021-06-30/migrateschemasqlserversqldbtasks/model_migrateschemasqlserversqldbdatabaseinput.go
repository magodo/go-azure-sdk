package migrateschemasqlserversqldbtasks

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type MigrateSchemaSqlServerSqlDbDatabaseInput struct {
	Name               *string                 `json:"name,omitempty"`
	SchemaSetting      *SchemaMigrationSetting `json:"schemaSetting,omitempty"`
	TargetDatabaseName *string                 `json:"targetDatabaseName,omitempty"`
}
