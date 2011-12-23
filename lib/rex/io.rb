##
# $Id: io.rb 12554 2011-05-06 18:47:10Z jduck $
# 
# This file simply provides an autoload interface for the children 
# of Rex::IO
#
##
module Rex::IO
	autoload :Stream,              'rex/io/stream'
	autoload :StreamAbstraction,   'rex/io/stream_abstraction'
	autoload :StreamServer,        'rex/io/stream_server'

	autoload :BidirectionalPipe,   'rex/io/bidirectional_pipe'
	autoload :DatagramAbstraction, 'rex/io/datagram_abstraction'
	autoload :RingBuffer,          'rex/io/ring_buffer'
end
