package protocol

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
	"unicode"
)

func TestAccessoryIdentityMatchesXML(t *testing.T) {
	source, err := os.ReadFile("protocol/resources/xml/accessory_identity.xml")
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		XMLName xml.Name `xml:"resources"`
		Filters []struct {
			Manufacturer string `xml:"manufacturer,attr"`
			Model        string `xml:"model,attr"`
			Version      string `xml:"version,attr"`
		} `xml:"usb-accessory"`
		Info []struct {
			Description string `xml:"description,attr"`
			URI         string `xml:"uri,attr"`
			Serial      string `xml:"serial,attr"`
		} `xml:"accessory-info"`
	}
	if err := xml.Unmarshal(source, &identity); err != nil {
		t.Fatal(err)
	}
	if len(identity.Filters) != 1 || len(identity.Info) != 1 {
		t.Fatal("expected one usb-accessory and one accessory-info element")
	}
	filter, info := identity.Filters[0], identity.Info[0]
	for _, field := range []struct{ name, xml, constant string }{
		{"manufacturer", filter.Manufacturer, AccessoryManufacturer},
		{"model", filter.Model, AccessoryModel},
		{"version", filter.Version, AccessoryVersion},
		{"description", info.Description, AccessoryDescription},
		{"uri", info.URI, AccessoryURI},
		{"serial", info.Serial, AccessorySerial},
	} {
		if field.xml == "" || strings.IndexFunc(field.xml, unicode.IsControl) >= 0 {
			t.Errorf("%s must be nonempty and contain no control characters", field.name)
		}
		if field.constant != field.xml {
			t.Errorf("%s: Go constant is %q, XML has %q", field.name, field.constant, field.xml)
		}
	}
}
