##
# $Id: encoders.rb 12554 2011-05-06 18:47:10Z jduck $
#
# This file maps encoders for autoload
##
require 'rex'

module Rex::Encoders
	autoload :XorDword,         'rex/encoders/xor_dword'
	autoload :XorDwordAdditive, 'rex/encoders/xor_dword_additive'
end
