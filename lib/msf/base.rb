# -*- coding: binary -*-
###
#
# framework-base
# --------------
#
# The base library provides implementations for some of the default
# sessions, such as Shell, Meterpreter, DispatchNinja, and VNC.  These
# sessions are used by modules that come pre-packaged with the default
# module distribution of Metasploit and are depended on by their
# respective payloads.
#
# Beyond providing the default sessions, framework-base also provides
# a wrapper interface to framework-core that makes some of the tasks,
# such as exploitation, into easier to manage functions.
#
###

# framework-base depends on framework-core
require 'msf/core'

# Configuration
require 'msf/base/config'
require 'msf/base/logging'

module Msf
	# Simple wrapper
	autoload :Simple, 'msf/base/simple'

	# Sessions
	autoload :Sessions, 'msf/base/sessions'

	# Serialization
	autoload :Serializer, 'msf/base/serializer/readable_text'

	# Persistent Storage
	autoload :PersistentStorage, 'msf/base/persistent_storage'

	# Utilities
	autoload :Util, 'msf/util'
end

