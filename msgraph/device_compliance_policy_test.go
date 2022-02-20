package msgraph_test

import (
	"fmt"
	"testing"

	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/internal/utils"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
)

func TestDeviceCompliancePolicy(t *testing.T) {
	c := test.NewTest(t)
	defer c.CancelFunc()

	testDeviceCompliancePolicyList(t, c)
	win10_policy := testWindows10CompliancePolicyCreate(t, c)

	t.Logf("New windows 10 policy ID:%s Name:%s\n",
		*win10_policy.ID, *win10_policy.DisplayName)

	ios_policy := testIOSCompliancePolicyCreate(t, c)
	t.Logf("New iOS policy ID:%s Name:%s\n",
		*ios_policy.ID, *ios_policy.DisplayName)

	testDeviceCompliancePolicyUpdate(t, c, *win10_policy.ID, odata.ShortTypeDeviceCompliancePolicyWindows10)
	testDeviceCompliancePolicyUpdate(t, c, *ios_policy.ID, odata.ShortTypeDeviceCompliancePolicyIOS)

	testDeviceCompliancePolicyGet(t, c, *win10_policy.ID)
	testDeviceCompliancePolicyGet(t, c, *ios_policy.ID)

	testDeviceCompliancePolicyAddAssignments(t, c, *win10_policy.ID)
	testDeviceCompliancePolicyAddAssignments(t, c, *ios_policy.ID)

	testDeviceCompliancePolicyListAssignments(t, c, *win10_policy.ID)
	testDeviceCompliancePolicyListAssignments(t, c, *ios_policy.ID)

	testDeviceCompliancePolicyDelete(t, c, *win10_policy.ID)
	testDeviceCompliancePolicyDelete(t, c, *ios_policy.ID)
}

func testDeviceCompliancePolicyList(t *testing.T, c *test.Test) {
	// In order to get the assignments and scheduled action policies/configurations,
	// one needs to use the $expand odata arg.
	query := odata.Query{Expand: odata.Expand{Relationship: "assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)"}}
	policies, _, err := c.DeviceCompliancePolicyClient.List(c.Context, query)

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.List(): %v", err)
	} else if policies == nil {
		t.Fatalf("DeviceCompliancePolicyClient: policies was nil")
	}
}

func testWindows10CompliancePolicyCreate(t *testing.T, c *test.Test) *msgraph.Windows10DeviceCompliancePolicy {
	// A new Compliance Policy *must* have one ScheduledActionForRule with a block rule.

	policy := msgraph.NewWindows10CompliancePolicy(utils.StringPtr(fmt.Sprintf("test-win10-policy-%s", c.RandomString)))

	block_action := msgraph.DeviceComplianceActionTypeBlock
	period_hours := int32(48)

	policy.ScheduledActionsForRule = &[]msgraph.DeviceManagementComplianceScheduledActionForRule{
		{
			msgraph.DirectoryObject{},
			nil,
			&[]msgraph.DeviceComplianceActionItem{
				{
					msgraph.DirectoryObject{},
					&block_action,
					&period_hours,
					nil,
					nil,
				},
			},
		},
	}

	new_policy, status, err := c.DeviceCompliancePolicyClient.CreateWindows10CompliancePolicy(c.Context, policy)
	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.CreateWindows10CompliancePolicy(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.CreateWindows10CompliancePolicy: invalid status: %d", status)
	}
	if new_policy == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateWindows10CompliancePolicy: policy was nil")
	}
	if new_policy.ID == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateWindows10CompliancePolicy: policy.Id was nil")
	}

	return new_policy
}

func testIOSCompliancePolicyCreate(t *testing.T, c *test.Test) *msgraph.IOSDeviceCompliancePolicy {
	// A new Compliance Policy *must* have one ScheduledActionForRule with a block rule.
	policy := msgraph.NewIOSCompliancePolicy(utils.StringPtr(fmt.Sprintf("test-ios-policy-%s", c.RandomString)))

	block_action := msgraph.DeviceComplianceActionTypeBlock
	period_hours := int32(96)

	policy.ScheduledActionsForRule = &[]msgraph.DeviceManagementComplianceScheduledActionForRule{
		{
			msgraph.DirectoryObject{},
			nil,
			&[]msgraph.DeviceComplianceActionItem{
				{
					msgraph.DirectoryObject{},
					&block_action,
					&period_hours,
					nil,
					nil,
				},
			},
		},
	}

	new_policy, status, err := c.DeviceCompliancePolicyClient.CreateIOSCompliancePolicy(c.Context, policy)
	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.CreateIOSCompliancePolicy(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.CreateIOSCompliancePolicy(): invalid status: %d", status)
	}
	if new_policy == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateIOSCompliancePolicy(): policy was nil")
	}
	if new_policy.ID == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateIOSCompliancePolicy(): policy.Id was nil")
	}

	return new_policy
}

func testDeviceCompliancePolicyGet(t *testing.T, c *test.Test, id string) {
	policy, status, err := c.DeviceCompliancePolicyClient.Get(c.Context, id, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.Get(): %v", err)
	} else if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.Get: invalid status: %d", status)
	} else if policy == nil {
		t.Fatal("DeviceCompliancePolicyClient.Get(): policy was nil")
	} else {
		base := policy.GetPolicyBase()
		t.Logf("Got policy id:%s name %s\n", *base.ID, *base.DisplayName)
	}

}

func testDeviceCompliancePolicyDelete(t *testing.T, c *test.Test, id string) {
	status, err := c.DeviceCompliancePolicyClient.Delete(c.Context, id)

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.Delete(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.Delete(): invalid status: %d", status)
	}
}

func testDeviceCompliancePolicyUpdate(t *testing.T, c *test.Test, id string, odata_short_type string) {
	var policy msgraph.DeviceCompliancePolicy

	switch odata_short_type {
	case odata.ShortTypeDeviceCompliancePolicyWindows10:
		win10_policy := msgraph.NewWindows10CompliancePolicy(nil)
		win10_policy.ID = &id
		win10_policy.DisplayName = utils.StringPtr(fmt.Sprintf("test-win10-policy-renamed-%s", c.RandomString))
		win10_policy.Description = utils.StringPtr(fmt.Sprintf("description for test-win10-policy-renamed-%s", c.RandomString))
		policy = win10_policy
	case odata.ShortTypeDeviceCompliancePolicyIOS:
		ios_policy := msgraph.NewIOSCompliancePolicy(nil)
		ios_policy.ID = &id
		ios_policy.DisplayName = utils.StringPtr(fmt.Sprintf("test-ios-policy-renamed-%s", c.RandomString))
		ios_policy.Description = utils.StringPtr(fmt.Sprintf("description for test-ios-policy-renamed-%s", c.RandomString))
		policy = ios_policy
	}

	status, err := c.DeviceCompliancePolicyClient.Update(c.Context, policy)

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.Update(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.Update(): invalid status: %d", status)
	}
}

func testDeviceCompliancePolicyListAssignments(t *testing.T, c *test.Test, id string) {
	assignments, status, err := c.DeviceCompliancePolicyClient.ListAssignments(c.Context, id, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.ListAssignments(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.ListAssignments(): invalid status: %d", status)
	}

	if assignments == nil {
		fmt.Printf("No assignments for policy %s\n", id)
	} else {
		for _, ass := range *assignments {
			fmt.Printf("%v\n", ass)
		}
	}
}

func testDeviceCompliancePolicyAddAssignments(t *testing.T, c *test.Test, id string) {
	assignments := []msgraph.DeviceCompliancePolicyAssignment{
		{Target: *msgraph.NewAllDevicesAssignmentTarget()}}

	status, err := c.DeviceCompliancePolicyClient.AddAssignments(c.Context, id, assignments)

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.AddAssignments(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.AddAssignments(): invalid status: %d", status)
	}
}
