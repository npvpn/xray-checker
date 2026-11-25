package subscription_test

import (
	"encoding/json"
	"strings"
	"testing"
	"xray-checker/subscription"
	"xray-checker/xray"
)

func TestJSONFragmentDialer(t *testing.T) {
	doc := `{"remarks":"probe","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"example.test","port":443,"id":"10101010-1010-4010-8010-101010101010"},"streamSettings":{"network":"tcp","sockopt":{"dialerProxy":"fragment"}}},{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"10-20","interval":"1-2"}}}]}`
	for _, input := range []string{doc, "[" + doc + "," + doc + "]"} {
		result, err := subscription.NewParser().Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := xray.NewConfigGenerator().GenerateConfig(result.Configs, 10000, "none")
		if err != nil {
			t.Fatal(err)
		}
		var generated struct {
			Outbounds []struct {
				Tag            string
				Protocol       string
				StreamSettings struct{ Sockopt struct{ DialerProxy string } }
				Settings       struct{ Fragment struct{ Length string } }
			}
		}
		if err = json.Unmarshal(raw, &generated); err != nil {
			t.Fatal(err)
		}
		helpers := map[string]string{}
		refs := map[string]bool{}
		for _, o := range generated.Outbounds {
			if o.Protocol == "freedom" {
				helpers[o.Tag] = o.Settings.Fragment.Length
			}
			if o.Protocol == "vless" {
				refs[o.StreamSettings.Sockopt.DialerProxy] = true
			}
		}
		if len(refs) != len(result.Configs) {
			t.Fatal("shared or missing dialer", refs)
		}
		for ref := range refs {
			if ref == "" || helpers[ref] != "10-20" {
				t.Fatal("lost fragment helper", ref)
			}
		}
	}
	base, err := subscription.NewParser().Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.Replace(doc, `"length":"10-20","interval":"1-2"`, `"interval":"1-2","length":"10-20"`, 1)
	reorderedResult, err := subscription.NewParser().Parse(reordered)
	if err != nil || reorderedResult.Configs[0].StableID != base.Configs[0].StableID {
		t.Fatal("unstable fragment ID", err)
	}
	changed := strings.Replace(doc, `"length":"10-20"`, `"length":"11-21"`, 1)
	changedResult, err := subscription.NewParser().Parse(changed)
	if err != nil || changedResult.Configs[0].StableID == base.Configs[0].StableID {
		t.Fatal("fragment change did not affect ID", err)
	}
	broken := strings.Replace(doc, `"dialerProxy":"fragment"`, `"dialerProxy":"missing"`, 1)
	if _, err := subscription.NewParser().Parse(broken); err == nil {
		t.Fatal("unresolved helper accepted")
	}
}
