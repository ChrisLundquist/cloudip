// Package all blank-imports every reputation plugin so a single import registers
// them all. Import it for side effects:
//
//	import _ "github.com/ChrisLundquist/cloudip/plugins/reputation/all"
package all

import (
	_ "github.com/ChrisLundquist/cloudip/plugins/reputation/feodo"
	_ "github.com/ChrisLundquist/cloudip/plugins/reputation/spamhaus"
	_ "github.com/ChrisLundquist/cloudip/plugins/reputation/tor"
)
