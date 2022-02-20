package msgraph_test

import (
	"fmt"
	"testing"

	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/odata"
)

// Test ManagedDevices. As one cannot create one ManagedDevice programmatically
// it only tests getting the list of those.
func TestManagedDevice(t *testing.T) {
	c := test.NewTest(t)
	defer c.CancelFunc()

	testManagedDeviceList(t, c)
	testManagedDevicesWindowsProtectionState(t, c)
}

func testManagedDeviceList(t *testing.T, c *test.Test) {
	managed_devices, _, err := c.ManagedDeviceClient.List(c.Context, odata.Query{})
	if err != nil {
		t.Fatalf("ManagedDeviceClient.List(): %v", err)
	}
	if managed_devices == nil {
		t.Fatal("ManagedDeviceClient.List(): managed_devices was nil")
	}
}

func testManagedDevicesWindowsProtectionState(t *testing.T, c *test.Test) {
	managed_devices, _, err := c.ManagedDeviceClient.List(c.Context, odata.Query{})
	if err != nil {
		t.Fatalf("ManagedDeviceClient.List(): %v", err)
	}
	if managed_devices == nil {
		t.Fatal("ManagedDeviceClient.List(): managed_devices was nil")
	}

	fmt.Printf("n=%d\n", len(*managed_devices))

	for _, device := range *managed_devices {
		state, _, err := c.ManagedDeviceClient.GetWindowsProtectionState(c.Context, *device.ID, odata.Query{})

		if err != nil {
			t.Fatalf("ManagedDeviceClient.GetWindowsProtectionState(%s): %v", *device.ID, err)
		}
		if state == nil {
			t.Fatalf("ManagedDeviceClient.GetWindowsProtectionState(%s): state was nil", *device.ID)
		}

		fmt.Printf("%s\n", *device.ID)

	}
}
