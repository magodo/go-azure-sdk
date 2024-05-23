package metricnamespaces

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type MetricNamespace struct {
	Classification *NamespaceClassification `json:"classification,omitempty"`
	Id             *string                  `json:"id,omitempty"`
	Name           *string                  `json:"name,omitempty"`
	Properties     *MetricNamespaceName     `json:"properties,omitempty"`
	Type           *string                  `json:"type,omitempty"`
}
