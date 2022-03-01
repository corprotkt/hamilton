package msgraph_test

import (
	"fmt"
	"testing"

	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/internal/utils"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
)

func TestDeviceConfigurationSettings(t *testing.T) {
	c := test.NewTest(t)
	defer c.CancelFunc()

	created := testCreateConfigurationSettings(t, c)

	testConfigurationSettingsAssignment(t, c, created.ID)

	testConfigurationSettingsList(t, c)

	testListReusableSettings(t, c)
}

func testListReusableSettings(t *testing.T, c *test.Test) {
	settings, status, err := c.DeviceConfigurationSettingsClient.ListReusableSettings(c.Context, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceCompliancePolicyClient.ListReusableSettings(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceCompliancePolicyClient.ListReusableSettings(): invalid status: %d", status)
	} else if settings == nil {
		t.Fatal("DeviceConfigurationSettingsClient.ListListReusableSettings(): nil list received")
	}
}

func testConfigurationSettingsList(t *testing.T, c *test.Test) {
	configs, status, err := c.DeviceConfigurationSettingsClient.List(c.Context, odata.Query{})

	if err != nil {
		t.Fatalf("DeviceConfigurationSettingsClient.List(): %v", err)
	} else if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationSettingsClient.List(): invalid status: %d", status)
	} else if configs != nil {
		for _, d := range *configs {
			_, status, err := c.DeviceConfigurationSettingsClient.GetConfigurationPolicyItems(c.Context, *d.ID, odata.Query{})
			if err != nil {
				t.Fatalf("DeviceConfigurationSettingsClient.GetConfigurationPolicyItems(): %v", err)
			}
			if status < 200 || status >= 300 {
				t.Fatalf("DeviceConfigurationSettingsClient.GetConfigurationPolicyItems(): invalid status: %d", status)
			} else {
				assigns, status, err := c.DeviceConfigurationSettingsClient.ListAssignments(c.Context, *d.ID, odata.Query{})
				if err != nil {
					t.Fatalf("DeviceCompliancePolicyClient.GetConfigurationPolicyItems(): %v", err)
				}
				if status < 200 || status >= 300 {
					t.Fatalf("DeviceCompliancePolicyClient.GetConfigurationPolicyItems(): invalid status: %d", status)
				} else if assigns == nil {
					t.Fatal("DeviceConfigurationSettingsClient.ListAssignments(): nil list received")
				}
			}
		}
	} else {
		t.Fatal("DeviceConfigurationSettingsClient.List(): nil list received")
	}
}

func testConfigurationSettingsAssignment(t *testing.T, c *test.Test, id *string) {
	assignments := []msgraph.DeviceCompliancePolicyAssignment{
		{Target: *msgraph.NewAllDevicesAssignmentTarget()},
	}

	status, err := c.DeviceConfigurationSettingsClient.AddAssignments(c.Context, *id, assignments)

	if err != nil {
		t.Fatalf("DeviceConfigurationSettingsClient.AddAssignments(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationSettingsClient.AddAssignments(): invalid status: %d", status)
	}
}

func testCreateConfigurationSettings(t *testing.T, c *test.Test) *msgraph.DeviceManagementConfigurationPolicy {
	choice := msgraph.DeviceManagementConfigurationChoiceSettingInstance{}
	choice.ODataType = utils.StringPtr(odata.TypeDeviceManagementConfigurationChoiceSettingInstance)
	choice.SettingDefinitionId = utils.StringPtr("device_vendor_msft_policy_config_accounts_allowmicrosoftaccountconnection")
	choice.ChoiceSettingValue = &msgraph.DeviceManagementConfigurationChoiceSettingValue{Value: utils.StringPtr("device_vendor_msft_policy_config_accounts_allowmicrosoftaccountconnection_0")}

	config := msgraph.DeviceManagementConfigurationPolicy{
		Name:         utils.StringPtr(fmt.Sprintf("test-configuration-settings-%s", c.RandomString)),
		Technologies: utils.StringPtr(msgraph.DeviceManagementConfigurationTechnologiesMdm),
		Platforms:    utils.StringPtr(msgraph.DeviceManagementConfigurationPlatformsWindows10),
		Settings: &[]msgraph.DeviceManagementConfigurationSetting{
			{SettingInstance: choice}}}

	created_config, status, err := c.DeviceConfigurationSettingsClient.Create(c.Context, &config)

	if err != nil {
		t.Fatalf("DeviceConfigurationSettingsClient.Create(): %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("DeviceConfigurationSettingsClient.Create(): invalid status: %d", status)
	}
	if created_config == nil {
		t.Fatal("DeviceConfigurationSettingsClient.Create(): configuration was nil")
	}
	if created_config.ID == nil {
		t.Fatal("DeviceConfigurationSettingsClient.Create(): configuration.ID was nil")
	}

	return created_config
}
