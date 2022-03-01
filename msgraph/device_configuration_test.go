package msgraph_test

import (
	"fmt"
	"testing"

	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/internal/utils"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
)

func TestDeviceConfiguration(t *testing.T) {
	c := test.NewTest(t)
	defer c.CancelFunc()

	testDeviceConfigurationList(t, c)
	config_win10 := testDeviceConfigurationCreateWin10(t, c)

	testDeviceConfigurationGet(t, c, *config_win10.ID)

	config_update := msgraph.NewWindows10GeneralConfiguration(nil)
	config_update.ID = config_win10.ID
	config_update.Description = utils.StringPtr("amended configuration")
	minLength := int32(10)
	config_update.PasswordMinimumLength = &minLength
	testDeviceConfigurationUpdate(t, c, config_update)

	testConfigurationAssignment(t, c, config_update.ID)

	testDeviceConfigurationDelete(t, c, *config_win10.ID)
}

func testConfigurationAssignment(t *testing.T, c *test.Test, id *string) {
	assignments := []msgraph.DeviceCompliancePolicyAssignment{
		{Target: *msgraph.NewAllDevicesAssignmentTarget()},
	}

	status, err := c.DeviceConfigurationClient.AddAssignments(c.Context, *id, assignments)

	if err != nil {
		t.Fatalf("DeviceConfigurationClient.AddAssignments(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationClient.AddAssignments(): invalid status: %d", status)
	}
}

func testDeviceConfigurationList(t *testing.T, c *test.Test) {
	policies, _, err := c.DeviceConfigurationClient.List(c.Context, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceConfigurationClient.List(): %v", err)
	} else if policies == nil {
		t.Fatalf("DeviceConfigurationClient: policies was nil")
	}
}

func testDeviceConfigurationCreateWin10(t *testing.T, c *test.Test) *msgraph.Windows10GeneralConfiguration {
	config := msgraph.NewWindows10GeneralConfiguration(utils.StringPtr(fmt.Sprintf("test-win10-general-config-%s", c.RandomString)))

	created_config, status, err := c.DeviceConfigurationClient.CreateWindows10GeneralConfiguration(c.Context, config)

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.CreateWindows10GeneralConfiguration(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.CreateWindows10GeneralConfiguration: invalid status: %d", status)
	}
	if created_config == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateWindows10GeneralConfiguration: configuration was nil")
	}
	if created_config.ID == nil {
		t.Fatal("DeviceCompliancePolicyClient.CreateWindows10GeneralConfiguration: configuration.ID was nil")
	}

	return created_config
}

func testDeviceConfigurationGet(t *testing.T, c *test.Test, id string) {
	config, status, err := c.DeviceConfigurationClient.Get(c.Context, id, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceConfigurationClient.Get(): %v", err)
	} else if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationClient.Get: invalid status: %d", status)
	} else if config == nil {
		t.Fatal("DeviceConfigurationClient.Get(): policy was nil")
	}
}

func testDeviceConfigurationUpdate(t *testing.T, c *test.Test, config msgraph.DeviceConfiguration) {
	status, err := c.DeviceConfigurationClient.Update(c.Context, config)

	if err != nil {
		t.Fatalf("DeviceConfigurationClient.Update(): %v", err)
	} else if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationClient.Update: invalid status: %d", status)
	}
}

func testDeviceConfigurationDelete(t *testing.T, c *test.Test, id string) {
	status, err := c.DeviceConfigurationClient.Delete(c.Context, id)

	if err != nil {
		t.Fatalf("DeviceConfigurationClient.Delete(): %v", err)
	} else if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationClient.Delete: invalid status: %d", status)
	}
}
