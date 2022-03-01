package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/manicminer/hamilton/odata"
)

type DeviceConfigurationSettingsClient struct {
	BaseClient Client
}

// NewDeviceConfigurationClient returns a new DeviceConfigurationClient.
func NewDeviceConfigurationSettingsClient(tenantId string) *DeviceConfigurationSettingsClient {
	return &DeviceConfigurationSettingsClient{
		BaseClient: NewClient(VersionBeta, tenantId),
	}
}

// List DeviceManagementConfigurationPolicies
func (c *DeviceConfigurationSettingsClient) List(ctx context.Context, query odata.Query) (*[]DeviceManagementConfigurationPolicy, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		DisablePaging:    query.Top > 0,
		OData:            query,
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      "/deviceManagement/configurationPolicies",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		ConfigurationPolicies *[]DeviceManagementConfigurationPolicy `json:"value"`
	}

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return data.ConfigurationPolicies, status, nil
}

func (c *DeviceConfigurationSettingsClient) Get(ctx context.Context, id string, query odata.Query) (*DeviceManagementConfigurationPolicy, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceConfigurations/configurationPolicies/%s", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.GetConfigurationPolicy(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var config DeviceManagementConfigurationPolicy

	if err := json.Unmarshal(respBody, &config); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	} else {

		return &config, status, nil
	}
}

func (c *DeviceConfigurationSettingsClient) GetConfigurationPolicyItems(ctx context.Context, id string, query odata.Query) (*[]DeviceManagementConfigurationSettingInstance, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/configurationPolicies/%s/settings", id),
			HasTenantId: true,
		},
	})

	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.GetConfigurationPolicyItems(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	// A duplica of DeviceManagementConfigurationItem but with a
	// json.RawMessage
	type tempItem struct {
		ID         *string         `json:"id,omitempty"`
		RawSetting json.RawMessage `json:"settingInstance,omitempty"`
	}

	var data struct {
		RawValues *[]tempItem `json:"value,omitempty"`
	}

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	} else {

		result := []DeviceManagementConfigurationSettingInstance{}

		for _, item := range *data.RawValues {
			a, err := newFunction(item.RawSetting)

			if err != nil {
				return nil, 0, err
			} else {
				result = append(result, a)
			}
		}
		return &result, status, nil
	}
}

func newFunction(item json.RawMessage) (DeviceManagementConfigurationSettingInstance, error) {
	var o struct {
		ODataType          *string `json:"@odata.type,omitempty"`
		ChoiceSettingValue *struct {
			Children *[]json.RawMessage `json:"children,omitempty"`
		} `json:"choiceSettingValue,omitempty"`
	}

	var result DeviceManagementConfigurationSettingInstance
	if err := json.Unmarshal(item, &o); err != nil {
		return nil, err
	}

	switch *o.ODataType {
	case odata.TypeDeviceManagementConfigurationSimpleSettingInstance:
		var a DeviceManagementConfigurationSimpleSettingInstance

		json.Unmarshal(item, &a)

		result = a
	case odata.TypeDeviceManagementConfigurationChoiceSettingInstance:
		var a DeviceManagementConfigurationChoiceSettingInstance

		json.Unmarshal(item, &a)

		if o.ChoiceSettingValue.Children != nil && len(*o.ChoiceSettingValue.Children) > 0 {
			var children []DeviceManagementConfigurationSettingInstance

			for _, c := range *o.ChoiceSettingValue.Children {
				child, err := newFunction(c)
				if err != nil {
					return nil, err
				} else {
					children = append(children, child)
				}
			}

			a.ChoiceSettingValue.Children = &children
		}

		result = a

	}

	return result, nil
}

func (c *DeviceConfigurationSettingsClient) Create(ctx context.Context,
	config *DeviceManagementConfigurationPolicy) (*DeviceManagementConfigurationPolicy, int, error) {
	var status int

	body, err := json.Marshal(config)
	if err != nil {
		return nil, status, fmt.Errorf("json.Marshal(): %v", err)
	}

	resp, status, _, err := c.BaseClient.Post(ctx, PostHttpRequestInput{
		Body: body,
		OData: odata.Query{
			Metadata: odata.MetadataFull,
		},
		ValidStatusCodes: []int{http.StatusCreated},
		Uri: Uri{
			Entity:      "/deviceManagement/configurationPolicies",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationSettingsClient.BaseClient.Post(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newConfiguration DeviceManagementConfigurationPolicy
	if err := json.Unmarshal(respBody, &newConfiguration); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newConfiguration, status, nil
}

// Lists ReusableSettings
func (c *DeviceConfigurationSettingsClient) ListReusableSettings(ctx context.Context, query odata.Query) (*[]DeviceManagementConfigurationSettingDefinition, int, error) {
	return c.listSettings(ctx, query, "reusableSettings")
}

// Lists ConfigurationSettings
func (c *DeviceConfigurationSettingsClient) ListConfigurationSettings(ctx context.Context, query odata.Query) (*[]DeviceManagementConfigurationSettingDefinition, int, error) {
	return c.listSettings(ctx, query, "configurationSettings")
}

func (c *DeviceConfigurationSettingsClient) listSettings(ctx context.Context, query odata.Query, kind string) (*[]DeviceManagementConfigurationSettingDefinition, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/%s", kind),
			HasTenantId: true,
		},
	})

	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.ListReusableSettings(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var raw_result struct {
		Values []json.RawMessage `json:"value"`
	}

	var result []DeviceManagementConfigurationSettingDefinition

	if err := json.Unmarshal(respBody, &raw_result); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	} else {
		for _, value := range raw_result.Values {
			var data struct {
				Type string `json:"@odata.type"`
			}
			if err = json.Unmarshal(value, &data); err == nil {
				switch data.Type {
				case odata.TypeDeviceManagementConfigurationSimpleSettingDefinition:
					var def DeviceManagementConfigurationSimpleSettingDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				case odata.TypeDeviceManagementConfigurationChoiceSettingDefinition:
					var def DeviceManagementConfigurationChoiceSettingDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				case odata.TypeDeviceManagementConfigurationChoiceSettingCollectionDefinition:
					var def DeviceManagementConfigurationChoiceSettingCollectionDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				case odata.TypeDeviceManagementConfigurationSimpleSettingCollectionDefinition:
					var def DeviceManagementConfigurationSimpleSettingCollectionDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				case odata.TypeDeviceManagementConfigurationSettingGroupCollectionDefinition:
					var def DeviceManagementConfigurationSettingGroupCollectionDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				case odata.TypeDeviceManagementConfigurationRedirectSettingDefinition:
					var def DeviceManagementConfigurationRedirectSettingDefinition
					if err = json.Unmarshal(value, &def); err == nil {
						result = append(result, def)
					}
				default:
					err = fmt.Errorf("DeviceConfigurationClient.BaseClient.ListReusableSettings(): unexpected type %s", data.Type)
				}

				if err != nil {
					return nil, status, fmt.Errorf("setting definition unmarshal error: %v", err)
				}
			}
		}
	}

	return &result, status, nil
}

func (c *DeviceConfigurationSettingsClient) AddAssignments(ctx context.Context, id string, assignments []DeviceCompliancePolicyAssignment) (int, error) {
	return c.BaseClient.AddAssignments(ctx, "/deviceManagement/configurationPolicies", id, assignments)
}

func (c *DeviceConfigurationSettingsClient) ListAssignments(ctx context.Context, id string, query odata.Query) (*[]DeviceCompliancePolicyAssignment, int, error) {
	return c.BaseClient.ListAssignments(ctx, "/deviceManagement/configurationPolicies", id, query)
}
