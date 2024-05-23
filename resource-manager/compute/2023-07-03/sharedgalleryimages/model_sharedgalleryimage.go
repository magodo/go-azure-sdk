package sharedgalleryimages

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SharedGalleryImage struct {
	Identifier *SharedGalleryIdentifier      `json:"identifier,omitempty"`
	Location   *string                       `json:"location,omitempty"`
	Name       *string                       `json:"name,omitempty"`
	Properties *SharedGalleryImageProperties `json:"properties,omitempty"`
}
