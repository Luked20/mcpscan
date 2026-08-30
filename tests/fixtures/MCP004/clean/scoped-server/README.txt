A separate manifest file on purpose.

MCP004's scope exemption is manifest-wide: one tool declaring "Only works
within allowed directories" exempts every path parameter in the same file.
Putting these tools in ../tools.json would therefore have exempted every
other clean case in that file too, and it would have passed for the wrong
reason -- the fixture would no longer prove anything about pattern/enum/
const/format constraints or about non-file tools.

Modelled on the official @modelcontextprotocol/server-filesystem, which is
what surfaced this in the regression corpus (tests/corpus/).
