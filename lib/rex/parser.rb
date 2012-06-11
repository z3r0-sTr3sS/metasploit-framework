##
# $Id: parser.rb 12554 2011-05-06 18:47:10Z jduck $
#
# This file maps parsers for autoload
##

module Rex
module Parser
	# General parsers
	autoload :Arguments, 'rex/parser/arguments'
	autoload :Ini,       'rex/parser/ini'

	# Nokogiri based data importers
	autoload :AcunetixDocument,          'rex/parser/acunetix_nokogiri'
	autoload :AppscanDocument,           'rex/parser/appscan_nokogiri'
	autoload :BurpSessionDocument,       'rex/parser/burp_session_nokogiri'
	autoload :CIDocument,                'rex/parser/ci_nokogiri'
	autoload :FoundstoneDocument,        'rex/parser/foundstone_nokogiri'
	autoload :FusionVMDocument,          'rex/parser/fusionvm_nokogiri'
	autoload :MbsaDocument,              'rex/parser/mbsa_nokogiri'
	autoload :NexposeRawDocument,        'rex/parser/nexpose_raw_nokogiri'
	autoload :NexposeSimpleDocument,     'rex/parser/nexpose_simple_nokogiri'
	autoload :NmapDocument,              'rex/parser/nmap_nokogiri'
	autoload :OpenVASDocument,           'rex/parser/openvas_nokogiri'
	autoload :WapitiDocument,            'rex/parser/wapiti_nokogiri'

	# Legacy XML parsers -- these will be converted some day
	autoload :NmapXMLStreamParser,       'rex/parser/nmap_xml'
	autoload :NexposeXMLStreamParser,    'rex/parser/nexpose_xml'
	autoload :RetinaXMLStreamParser,     'rex/parser/retina_xml'
	autoload :NetSparkerXMLStreamParser, 'rex/parser/netsparker_xml'
	autoload :NessusXMLStreamParser,     'rex/parser/nessus_xml'
	autoload :IP360XMLStreamParser,      'rex/parser/ip360_xml'
	autoload :IP360ASPLXMLStreamParser,  'rex/parser/ip360_aspl_xml'

	# Other data importers
	autoload :AppleBackupManifestDB,     'rex/parser/apple_backup_manifestdb'
end
end
