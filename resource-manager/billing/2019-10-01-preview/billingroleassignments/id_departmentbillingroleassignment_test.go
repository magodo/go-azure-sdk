package billingroleassignments

import (
	"testing"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = &DepartmentBillingRoleAssignmentId{}

func TestNewDepartmentBillingRoleAssignmentID(t *testing.T) {
	id := NewDepartmentBillingRoleAssignmentID("billingAccountValue", "departmentValue", "billingRoleAssignmentValue")

	if id.BillingAccountName != "billingAccountValue" {
		t.Fatalf("Expected %q but got %q for Segment 'BillingAccountName'", id.BillingAccountName, "billingAccountValue")
	}

	if id.DepartmentName != "departmentValue" {
		t.Fatalf("Expected %q but got %q for Segment 'DepartmentName'", id.DepartmentName, "departmentValue")
	}

	if id.BillingRoleAssignmentName != "billingRoleAssignmentValue" {
		t.Fatalf("Expected %q but got %q for Segment 'BillingRoleAssignmentName'", id.BillingRoleAssignmentName, "billingRoleAssignmentValue")
	}
}

func TestFormatDepartmentBillingRoleAssignmentID(t *testing.T) {
	actual := NewDepartmentBillingRoleAssignmentID("billingAccountValue", "departmentValue", "billingRoleAssignmentValue").ID()
	expected := "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments/billingRoleAssignmentValue"
	if actual != expected {
		t.Fatalf("Expected the Formatted ID to be %q but got %q", expected, actual)
	}
}

func TestParseDepartmentBillingRoleAssignmentID(t *testing.T) {
	testData := []struct {
		Input    string
		Error    bool
		Expected *DepartmentBillingRoleAssignmentId
	}{
		{
			// Incomplete URI
			Input: "",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments",
			Error: true,
		},
		{
			// Valid URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments/billingRoleAssignmentValue",
			Expected: &DepartmentBillingRoleAssignmentId{
				BillingAccountName:        "billingAccountValue",
				DepartmentName:            "departmentValue",
				BillingRoleAssignmentName: "billingRoleAssignmentValue",
			},
		},
		{
			// Invalid (Valid Uri with Extra segment)
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments/billingRoleAssignmentValue/extra",
			Error: true,
		},
	}
	for _, v := range testData {
		t.Logf("[DEBUG] Testing %q", v.Input)

		actual, err := ParseDepartmentBillingRoleAssignmentID(v.Input)
		if err != nil {
			if v.Error {
				continue
			}

			t.Fatalf("Expect a value but got an error: %+v", err)
		}
		if v.Error {
			t.Fatal("Expect an error but didn't get one")
		}

		if actual.BillingAccountName != v.Expected.BillingAccountName {
			t.Fatalf("Expected %q but got %q for BillingAccountName", v.Expected.BillingAccountName, actual.BillingAccountName)
		}

		if actual.DepartmentName != v.Expected.DepartmentName {
			t.Fatalf("Expected %q but got %q for DepartmentName", v.Expected.DepartmentName, actual.DepartmentName)
		}

		if actual.BillingRoleAssignmentName != v.Expected.BillingRoleAssignmentName {
			t.Fatalf("Expected %q but got %q for BillingRoleAssignmentName", v.Expected.BillingRoleAssignmentName, actual.BillingRoleAssignmentName)
		}

	}
}

func TestParseDepartmentBillingRoleAssignmentIDInsensitively(t *testing.T) {
	testData := []struct {
		Input    string
		Error    bool
		Expected *DepartmentBillingRoleAssignmentId
	}{
		{
			// Incomplete URI
			Input: "",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe/dEpArTmEnTs",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe/dEpArTmEnTs/dEpArTmEnTvAlUe",
			Error: true,
		},
		{
			// Incomplete URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments",
			Error: true,
		},
		{
			// Incomplete URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe/dEpArTmEnTs/dEpArTmEnTvAlUe/bIlLiNgRoLeAsSiGnMeNtS",
			Error: true,
		},
		{
			// Valid URI
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments/billingRoleAssignmentValue",
			Expected: &DepartmentBillingRoleAssignmentId{
				BillingAccountName:        "billingAccountValue",
				DepartmentName:            "departmentValue",
				BillingRoleAssignmentName: "billingRoleAssignmentValue",
			},
		},
		{
			// Invalid (Valid Uri with Extra segment)
			Input: "/providers/Microsoft.Billing/billingAccounts/billingAccountValue/departments/departmentValue/billingRoleAssignments/billingRoleAssignmentValue/extra",
			Error: true,
		},
		{
			// Valid URI (mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe/dEpArTmEnTs/dEpArTmEnTvAlUe/bIlLiNgRoLeAsSiGnMeNtS/bIlLiNgRoLeAsSiGnMeNtVaLuE",
			Expected: &DepartmentBillingRoleAssignmentId{
				BillingAccountName:        "bIlLiNgAcCoUnTvAlUe",
				DepartmentName:            "dEpArTmEnTvAlUe",
				BillingRoleAssignmentName: "bIlLiNgRoLeAsSiGnMeNtVaLuE",
			},
		},
		{
			// Invalid (Valid Uri with Extra segment - mIxEd CaSe since this is insensitive)
			Input: "/pRoViDeRs/mIcRoSoFt.bIlLiNg/bIlLiNgAcCoUnTs/bIlLiNgAcCoUnTvAlUe/dEpArTmEnTs/dEpArTmEnTvAlUe/bIlLiNgRoLeAsSiGnMeNtS/bIlLiNgRoLeAsSiGnMeNtVaLuE/extra",
			Error: true,
		},
	}
	for _, v := range testData {
		t.Logf("[DEBUG] Testing %q", v.Input)

		actual, err := ParseDepartmentBillingRoleAssignmentIDInsensitively(v.Input)
		if err != nil {
			if v.Error {
				continue
			}

			t.Fatalf("Expect a value but got an error: %+v", err)
		}
		if v.Error {
			t.Fatal("Expect an error but didn't get one")
		}

		if actual.BillingAccountName != v.Expected.BillingAccountName {
			t.Fatalf("Expected %q but got %q for BillingAccountName", v.Expected.BillingAccountName, actual.BillingAccountName)
		}

		if actual.DepartmentName != v.Expected.DepartmentName {
			t.Fatalf("Expected %q but got %q for DepartmentName", v.Expected.DepartmentName, actual.DepartmentName)
		}

		if actual.BillingRoleAssignmentName != v.Expected.BillingRoleAssignmentName {
			t.Fatalf("Expected %q but got %q for BillingRoleAssignmentName", v.Expected.BillingRoleAssignmentName, actual.BillingRoleAssignmentName)
		}

	}
}

func TestSegmentsForDepartmentBillingRoleAssignmentId(t *testing.T) {
	segments := DepartmentBillingRoleAssignmentId{}.Segments()
	if len(segments) == 0 {
		t.Fatalf("DepartmentBillingRoleAssignmentId has no segments")
	}

	uniqueNames := make(map[string]struct{}, 0)
	for _, segment := range segments {
		uniqueNames[segment.Name] = struct{}{}
	}
	if len(uniqueNames) != len(segments) {
		t.Fatalf("Expected the Segments to be unique but got %q unique segments and %d total segments", len(uniqueNames), len(segments))
	}
}
