// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// definedTagKey is a defined tag as Terraform writes it: "Namespace.key".
var definedTagKey = regexp.MustCompile(`^[^.\s]+\.[^.\s]+$`)

// definedTagsToOCI turns {"FinOps.stack" = "infra"} into OCI's {"FinOps": {"stack": "infra"}}.
func definedTagsToOCI(tags map[string]string) (map[string]map[string]interface{}, error) {
	out := map[string]map[string]interface{}{}
	for k, v := range tags {
		ns, key, ok := strings.Cut(k, ".")
		if !ok || !definedTagKey.MatchString(k) {
			return nil, fmt.Errorf("defined tag %q must be written as Namespace.key", k)
		}
		if out[ns] == nil {
			out[ns] = map[string]interface{}{}
		}
		out[ns][key] = v
	}
	return out, nil
}

// definedTagsFromOCI flattens OCI's defined tags and leaves out the ignored ones.
func definedTagsFromOCI(tags map[string]map[string]interface{}, ignore map[string]bool) map[string]string {
	out := map[string]string{}
	for ns, keys := range tags {
		for key, v := range keys {
			k := ns + "." + key
			if !ignore[k] {
				out[k] = fmt.Sprint(v)
			}
		}
	}
	return out
}

// keepIgnoredDefinedTags adds to the desired tags the ignored ones that the NSG has
// in OCI. OCI replaces all the defined tags on update, so without them an update
// would delete the tags that OCI or someone else set (e.g. Oracle-Tags.CreatedBy).
func keepIgnoredDefinedTags(desired map[string]string, live map[string]map[string]interface{}, ignore map[string]bool) map[string]string {
	out := make(map[string]string, len(desired))
	for k, v := range desired {
		out[k] = v
	}
	for ns, keys := range live {
		for key, v := range keys {
			if k := ns + "." + key; ignore[k] {
				out[k] = fmt.Sprint(v)
			}
		}
	}
	return out
}

// tagsFromMap reads a known tags map. ok is false when the map is null or unknown,
// that is when the configuration leaves the tags to OCI.
func tagsFromMap(ctx context.Context, m types.Map) (tags map[string]string, ok bool, diags diag.Diagnostics) {
	if m.IsNull() || m.IsUnknown() {
		return nil, false, nil
	}
	tags = map[string]string{}
	diags = m.ElementsAs(ctx, &tags, false)
	return tags, true, diags
}

func tagsValue(ctx context.Context, tags map[string]string) (types.Map, diag.Diagnostics) {
	if tags == nil {
		tags = map[string]string{}
	}
	return types.MapValueFrom(ctx, types.StringType, tags)
}

// ocidRegion returns the region in an OCID such as ocid1.vcn.oc1.eu-madrid-1.aaaa,
// or "" when the OCID has none (global resources) or is not an OCID.
func ocidRegion(ocid string) string {
	parts := strings.Split(ocid, ".")
	if len(parts) < 5 || parts[0] != "ocid1" {
		return ""
	}
	return parts[3]
}

// checkRegion fails when an OCID belongs to another region than the provider
// configuration. OCI would answer with a 404 that does not say why.
func (d *providerData) checkRegion(attr, ocid string) error {
	r := ocidRegion(ocid)
	if r == "" || d.region == "" || common.StringToRegion(r) == common.StringToRegion(d.region) {
		return nil
	}
	return fmt.Errorf("%s %s is in region %s, but this provider configuration uses %s. "+
		"Use a provider configuration for %s, e.g. an alias with region = %q",
		attr, ocid, common.StringToRegion(r), d.region, common.StringToRegion(r), string(common.StringToRegion(r)))
}
