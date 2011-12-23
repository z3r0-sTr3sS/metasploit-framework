##
# $Id: sinks.rb 12554 2011-05-06 18:47:10Z jduck $
#
# Map log sinks for autload
##

module Rex
module Logging
module Sinks

	autoload :Flatfile, 'rex/logging/sinks/flatfile'
	autoload :Stderr,   'rex/logging/sinks/stderr'

end
end
end
