// Package all blank-imports every provider plugin so that a single import
// registers them all. Import it for side effects:
//
//	import _ "github.com/ChrisLundquist/cloudip/plugins/all"
package all

import (
	_ "github.com/ChrisLundquist/cloudip/plugins/aws"
	_ "github.com/ChrisLundquist/cloudip/plugins/azure"
	_ "github.com/ChrisLundquist/cloudip/plugins/gcp"
)
