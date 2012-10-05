# -*- coding: binary -*-
#
# Core
#
require 'pathname'
require 'fastlib'
require 'msf/core'
require 'msf/core/module_set'

#
# Project
#
#   - add unload support
#
###
class ModuleManager < Msf::ModuleSet

	require 'msf/core/payload_set'

	include Msf::Framework::Offspring

	#
	# Initializes an instance of the overall module manager using the supplied
	# framework instance. The types parameter can be used to only load specific
	# module types on initialization
	#
	def initialize(framework,types=MODULE_TYPES)
		self.module_paths         = []
		self.module_sets          = {}
		self.module_failed        = {}
		self.enabled_types        = {}
		self.framework            = framework
		self.cache                = {}

		types.each { |type|
			init_module_set(type)
		}

		super(nil)
	end

	def init_module_set(type)
		self.enabled_types[type] = true
		case type
		when MODULE_PAYLOAD
			instance = PayloadSet.new(self)
		else
			instance = ModuleSet.new(type)
		end

		self.module_sets[type] = instance

		# Set the module set's framework reference
		instance.framework = self.framework
	end

	#
	# Creates a module using the supplied name.
	#
	def create(name)
		# Check to see if it has a module type prefix.  If it does,
		# try to load it from the specific module set for that type.
		if (md = name.match(/^(#{MODULE_TYPES.join('|')})\/(.*)$/))
			module_sets[md[1]].create(md[2])
		# Otherwise, just try to load it by name.
		else
			super
		end
	end

	#
	# Accessors by module type
	#

	#
	# Returns all of the modules of the specified type
	#
	def module_set(type)
		module_sets[type]
	end

	#
	# Returns the set of loaded encoder module classes.
	#
	def encoders
		module_set(MODULE_ENCODER)
	end


	#
	# Returns the set of loaded exploit module classes.
	#
	def exploits
		module_set(MODULE_EXPLOIT)
	end

	#
	# Returns the set of loaded nop module classes.
	#
	def nops
		module_set(MODULE_NOP)
	end

	#
	# Returns the set of loaded payload module classes.
	#
	def payloads
		module_set(MODULE_PAYLOAD)
	end

	#
	# Returns the set of loaded auxiliary module classes.
	#
	def auxiliary
		module_set(MODULE_AUX)
	end

	#
	# Returns the set of loaded auxiliary module classes.
	#
	def post
		module_set(MODULE_POST)
	end

	#
	# Returns the set of modules that failed to load.
	#
	def failed
		return module_failed
	end

	##
	#
	# Module path management
	#
	##

	#
	# Adds a path to be searched for new modules.
	#
	def add_module_path(path)
		npaths = []
		
		if path =~ /\.fastlib$/
			unless ::File.exist?(path)
				raise RuntimeError, "The path supplied does not exist", caller
			end
			npaths << ::File.expand_path(path)
		else
			path.sub!(/#{File::SEPARATOR}$/, '')

			# Make the path completely canonical
			path = Pathname.new(File.expand_path(path))

			# Make sure the path is a valid directory
			unless path.directory?
				raise RuntimeError, "The path supplied is not a valid directory.", caller
			end

			# Now that we've confirmed it exists, get the full, cononical path
			path    = ::File.expand_path(path)
			npaths << path

			# Identify any fastlib archives inside of this path
			Dir["#{path}/**/*.fastlib"].each do |fp|
				npaths << fp
			end
		end

		# Update the module paths appropriately
		self.module_paths = (module_paths + npaths).flatten.uniq
	
		# Load all of the modules from the new paths
		counts = nil
		npaths.each { |d|
			counts = load_modules(d, false)
		}
		
		return counts
	end

	#
	# Removes a path from which to search for modules.
	#
	def remove_module_path(path)
		module_paths.delete(path)
		module_paths.delete(::File.expand_path(path))
	end

	def register_type_extension(type, ext)
	end

	#
	# Reloads modules from all module paths
	#
	def reload_modules

		self.module_history = {}
		self.clear

		self.enabled_types.each_key do |type|
			module_sets[type].clear
			init_module_set(type)
		end

		# The number of loaded modules in the following categories:
		# auxiliary/encoder/exploit/nop/payload/post
		count = 0
		module_paths.each do |path|
			mods = load_modules(path, true)
			mods.each_value {|c| count += c}
		end

		rebuild_cache

		count
	end

	#
	# Reloads the module specified in mod.  This can either be an instance of a
	# module or a module class.
	#
	def reload_module(mod)
		omod    = mod
		refname = mod.refname
		ds      = mod.datastore

		dlog("Reloading module #{refname}...", 'core')

		# Set the target file
		file = mod.file_path
		wrap = ::Module.new

		# Load the module into a new Module wrapper
		begin
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return false
				end
			end
		rescue ::Exception => e

			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to reload module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[mod.file_path] = errmsg
					return
				end
			end

			errmsg = "Failed to reload module from #{file}: #{e.class} #{e}"
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return
		end

		added = nil
		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Reloaded file did not contain a valid module (#{file})."
			elog(errmsg)
			self.module_failed[mod.file_path] = errmsg
			return nil
		end

		self.module_failed.delete(mod.file_path)

		# Remove the original reference to this module
		self.delete(mod.refname)

		# Indicate that the module is being loaded again so that any necessary
		# steps can be taken to extend it properly.
		on_module_load(added, mod.type, refname, {
			'files' => [ mod.file_path ],
			'noup'  => true})

		# Create a new instance of the module
		if (mod = create(refname))
			mod.datastore.update(ds)
		else
			elog("Failed to create instance of #{refname} after reload.", 'core')
			# Return the old module instance to avoid a strace trace
			return omod
		end

		# Let the specific module sets have an opportunity to handle the fact
		# that this module was reloaded.
		module_sets[mod.type].on_module_reload(mod)

		# Rebuild the cache for just this module
		rebuild_cache(mod)

		mod
	end

	#
	# Overrides the module set method for adding a module so that some extra
	# steps can be taken to subscribe the module and notify the event
	# dispatcher.
	#
	def add_module(mod, name, file_paths)
		# Call the module set implementation of add_module
		dup = super

		# Automatically subscribe a wrapper around this module to the necessary
		# event providers based on whatever events it wishes to receive.  We
		# only do this if we are the module manager instance, as individual
		# module sets need not subscribe.
		auto_subscribe_module(dup)

		# Notify the framework that a module was loaded
		framework.events.on_module_load(name, dup)
	end

	def fullname_to_paths(type, parts)
		files = []
		paths = []

		check_paths = module_paths
		#paths = [ Msf::Config.module_directory ]

		type_str = type.dup
		type_str << "s" if not [ MODULE_AUX, MODULE_POST ].include? type

		check_paths.each { |path|

			file_base = File.join(path, type_str)

			# Payloads get special treatment
			if type == MODULE_PAYLOAD
				# Try single first
				file = File.join(file_base, "singles", parts)
				file << ".rb"
				#puts "single? #{file.inspect}"
				if File.exists?(file)
					files << file
					paths << path
					next
				end

				# Is the payload staged?
				stager = parts.last
				#puts stager.inspect
				if stager =~ /^(reverse_|bind_|find_|passivex)/
					os = parts[0,1].first
					# Special case payloads (aliased handlers)
					# XXX: It would be ideal if this could be resolved without hardcoding it here.
					if os == "windows"
						case stager
						when "find_tag"
							stager = "findtag_ord"
						when "reverse_http"
							stager = "passivex"
						end
					end
					stage = parts[-2,1].first
					rest = parts[0, parts.length - 2]
					file1 = File.join(file_base, "stagers", rest, "#{stager}.rb")
					file2 = File.join(file_base, "stages", rest, "#{stage}.rb")
					#puts "staged:"
					#puts file1.inspect
					#puts file2.inspect
					next if not File.exists?(file1) or not File.exists?(file2)
					files << file1
					paths << path
					files << file2
					paths << path
				end

			else
				file = File.join(file_base, parts)
				file << ".rb"
				#puts "Not a payload: #{file.inspect}"
				next if not File.exists?(file)
				files << file
				paths << path

			end
		}

		ret = [ files, paths ]
		#puts "Returning: #{ret.inspect}"
		ret
	end

	#
	# Loads the files associated with a module and recalculates module
	# associations.
	#
	def demand_load_module(fullname, use_cache = true)
		#puts "in demand_load_module(#{fullname.inspect}, #{use_cache.inspect})"
		#puts caller.join("\n")
		dlog("Demand loading module #{fullname}.", 'core', LEV_1)

		parts  = fullname.split(/\//)
		type = parts.slice!(0,1).first
		files = []
		paths = []

		#$stderr.puts module_paths.inspect

		if use_cache
			return nil if (@modcache.group?(fullname) == false)
			return nil if (@modcache[fullname]['FileNames'].nil?)
			return nil if (@modcache[fullname]['FilePaths'].nil?)

			files = @modcache[fullname]['FileNames'].split(',')
			paths = @modcache[fullname]['FilePaths'].split(',')
		else
			files, paths = fullname_to_paths(type, parts)
			if files.length < 1
				return nil
			end
		end

		files.each_with_index { |file, idx|
			dlog("Loading from file #{file}", 'core', LEV_2)

			if not load_module_from_file(paths[idx], file, nil, nil, nil, true)
				return nil
			end
		}

		if (module_sets[type] and module_sets[type].postpone_recalc != true)
			module_sets[type].recalculate
		end

		return true
	end


	#
	# Provide a list of the types of modules in the set
	#
	def module_types
		module_sets.keys.dup
	end

	#
	# Provide a list of module names of a specific type
	#
	def module_names(set)
		module_sets[set] ? module_sets[set].keys.dup : []
	end

	#
	# Read the module code from the file on disk
	#
	def load_module_source(file)
		::File.read(file, ::File.size(file))
	end

	#
	# Rebuild the cache for the module set
	#
	def rebuild_cache(mod = nil)
		return if not (framework.db and framework.db.migrated)
		if mod
			framework.db.update_module_details(mod)
		else
			framework.db.update_all_module_details
		end
		refresh_cache
	end

	#
	# Return a listing of all cached modules
	#
	def cache_entries
		return {} if not (framework.db and framework.db.migrated)
		res = {}
		::Mdm::ModuleDetail.find(:all).each do |m|
			res[m.file] = { :mtype => m.mtype, :refname => m.refname, :file => m.file, :mtime => m.mtime }
			unless module_set(m.mtype).has_key?(m.refname)
				module_set(m.mtype)[m.refname] = SymbolicModule
			end
		end
	
		res
	end

	#
	# Reset the module cache
	#
	def refresh_cache
		self.cache = cache_entries
	end

	def has_module_file_changed?(file)
		begin 
			cfile = self.cache[file] 
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"
			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def has_archive_file_changed?(arch, file)
		begin 		
			cfile = self.cache[file]
			return true if not cfile

			# Payloads can't be cached due to stage/stager matching
			return true if cfile[:mtype] == "payload"

			return cfile[:mtime].to_i != ::File.mtime(file).to_i
		rescue ::Errno::ENOENT
			return true
		end
	end

	def demand_load_module(mtype, mname)
		n = self.cache.keys.select { |k| 
			self.cache[k][:mtype]   == mtype and 
			self.cache[k][:refname] == mname 
		}.first

		return nil unless n
		m = self.cache[n]

		path = nil
		if m[:file] =~ /^(.*)\/#{m[:mtype]}s?\//
			path = $1
			load_module_from_file(path, m[:file], nil, nil, nil, true)
		else
			dlog("Could not demand load module #{mtype}/#{mname} (unknown base name in #{m[:file]})", 'core', LEV_2)
			nil
		end
	end

	attr_accessor :cache # :nodoc:

protected


	#
	# Load all of the modules from the supplied directory or archive
	#
	def load_modules(bpath, demand = false)
		( bpath =~ /\.fastlib$/ ) ?
			load_modules_from_archive(bpath, demand) :
			load_modules_from_directory(bpath, demand)
	end

	#
	# Load all of the modules from the supplied module path (independent of
	# module type).
	#
	def load_modules_from_directory(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		dbase  = ::Dir.new(bpath)
		dbase.entries.each do |ent|
			next if ent.downcase == '.svn'

			path  = ::File.join(bpath, ent)
			mtype = ent.gsub(/s$/, '')

			next if not ::File.directory?(path)
			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Try to load modules from all the files in the supplied path
			Rex::Find.find(path) do |file|

				# Skip non-ruby files
				next if file[-3,3] != ".rb"

				# Skip unit test files
				next if (file =~ /rb\.(ut|ts)\.rb$/)

				# Skip files with a leading period
				next if file[0,1] == "."

				load_module_from_file(bpath, file, loaded, recalc, counts, demand)
			end
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end


	#
	# Load all of the modules from the supplied fastlib archive
	#
	def load_modules_from_archive(bpath, demand = false)
		loaded = {}
		recalc = {}
		counts = {}
		delay  = {}
		ks     = true

		::FastLib.list(bpath).each do |ent|

			next if ent.index(".svn/")

			mtype, path = ent.split("/", 2)
			mtype.sub!(/s$/, '')

			next if not MODULE_TYPES.include?(mtype)
			next if not enabled_types[mtype]

			# Skip non-ruby files
			next if ent[-3,3] != ".rb"

			# Skip unit test files
			next if (ent =~ /rb\.(ut|ts)\.rb$/)

			# Skip files with a leading period
			next if ent[0,1] == "."

			load_module_from_archive(bpath, ent, loaded, recalc, counts, demand)
		end

		recalc.each_key do |mtype|
			module_set(mtype).recalculate		
		end

		# Return per-module loaded counts
		return counts
	end

	#
	# Loads a module from the supplied file.
	#
	def load_module_from_file(path, file, loaded, recalc, counts, demand = false)

		if not ( demand or has_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Substitute the base path
		path_base = file.sub(path + File::SEPARATOR, '')

		# Derive the name from the path with the exclusion of the .rb
		name = path_base.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		path_base.sub!(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = path_base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = path_base
		end

		type.sub!(/s$/, '')


		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval(load_module_source(file), file)
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{file} due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

		# Do some processing on the loaded module to get it into the
		# right associations
		on_module_load(added, type, name, {
			'files' => [ file ],
			'paths' => [ path ],
			'type'  => type })

		# Set this module type as needing recalculation
		recalc[type] = true if (recalc)

		# Append the added module to the hash of file->module
		loaded[file] = added if (loaded)

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end


	#
	# Loads a module from the supplied archive path
	#
	def load_module_from_archive(path, file, loaded, recalc, counts, demand = false)
		
		if not ( demand or has_archive_module_file_changed?(file))
			dlog("Cached module from file #{file} has not changed.", 'core', LEV_2)
			return false
		end

		# Derive the name from the path with the exclusion of the .rb
		name = file.match(/^(.+?)#{File::SEPARATOR}(.*)(.rb?)$/)[2]

		# Chop off the file name
		base = file.sub(/(.+)(#{File::SEPARATOR}.+)(.rb?)$/, '\1')

		if (m = base.match(/^(.+?)#{File::SEPARATOR}+?/))
			type = m[1]
		else
			type = base
		end

		type.sub!(/s$/, '')

		added = nil

		begin
			wrap = ::Module.new
			wrap.module_eval( ::FastLib.load(path, file), file )
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file} due to version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Hide eval errors when the module version is not compatible
			if(wrap.const_defined?(:RequiredVersions))
				mins = wrap.const_get(:RequiredVersions)
				if( mins[0] > ::Msf::Framework::VersionCore or
				    mins[1] > ::Msf::Framework::VersionAPI
				  )
					errmsg = "Failed to load module from #{path}::#{file}due to error and failed version check (requires Core:#{mins[0]} API:#{mins[1]})"
					elog(errmsg)
					self.module_failed[file] = errmsg
					return false
				end
			end
			errmsg = "#{e.class} #{e}"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		::Msf::Framework::Major.downto(1) do |major|
			if wrap.const_defined?("Metasploit#{major}")
				added = wrap.const_get("Metasploit#{major}")
				break
			end
		end

		if not added
			errmsg = "Missing Metasploit class constant"
			self.module_failed[file] = errmsg
			elog(errmsg)
			return false
		end

		# If the module indicates that it is not usable on this system, then we
		# will not try to use it.
		usable = false

		begin
			usable = respond_to?(:is_usable) ? added.is_usable : true
		rescue
			elog("Exception caught during is_usable check: #{$!}")
		end

		if (usable == false)
			ilog("Skipping module in #{path}::#{file} because is_usable returned false.", 'core', LEV_1)
			return false
		end

		ilog("Loaded #{type} module #{added} from #{path}::#{file}.", 'core', LEV_2)
		self.module_failed.delete(file)

		# Do some processing on the loaded module to get it into the
		# right associations
		on_module_load(added, type, name, {
			'files' => [ file ],
			'paths' => [ path ],
			'type'  => type })

		# Set this module type as needing recalculation
		recalc[type] = true if (recalc)

		# Append the added module to the hash of file->module
		loaded[file] = added if (loaded)

		# The number of loaded modules this round
		if (counts)
			counts[type] = (counts[type]) ? (counts[type] + 1) : 1
		end

		return true
	end


	#
	# Called when a module is initially loaded such that it can be
	# categorized accordingly.
	#
	def on_module_load(mod, type, name, modinfo)
		# Payload modules require custom loading as the individual files
		# may not directly contain a logical payload that a user would
		# reference, such as would be the case with a payload stager or
		# stage.  As such, when payload modules are loaded they are handed
		# off to a special payload set.  The payload set, in turn, will
		# automatically create all the permutations after all the payload
		# modules have been loaded.
		
		if (type != MODULE_PAYLOAD)
			# Add the module class to the list of modules and add it to the
			# type separated set of module classes
			add_module(mod, name, modinfo)
		end

		module_sets[type].add_module(mod, name, modinfo)
	end

	#
	# This method automatically subscribes a module to whatever event providers
	# it wishes to monitor.  This can be used to allow modules to automatically
	# execute or perform other tasks when certain events occur.  For instance,
	# when a new host is detected, other aux modules may wish to run such
	# that they can collect more information about the host that was detected.
	#
	def auto_subscribe_module(mod)
		# If auto-subscribe has been disabled
		if (framework.datastore['DisableAutoSubscribe'] and
		    framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
			return
		end

		# If auto-subscription is enabled (which it is by default), figure out
		# if it subscribes to any particular interfaces.
		inst = nil

		#
		# Exploit event subscriber check
		#
		if (mod.include?(ExploitEvent) == true)
			framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
		end

		#
		# Session event subscriber check
		#
		if (mod.include?(SessionEvent) == true)
			framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
		end
	end

	attr_accessor :modules, :module_sets # :nodoc:
	attr_accessor :module_paths # :nodoc:
	attr_accessor :module_failed # :nodoc:
	attr_accessor :enabled_types # :nodoc:

end

module Msf
  # Upper management decided to throw in some middle management # because the modules were getting out of hand.  This
  # bad boy takes care of the work of managing the interaction with modules in terms of loading and instantiation.
  #
  # @todo add unload support
  class ModuleManager < ModuleSet
    require 'msf/core/payload_set'

    # require here so that Msf::ModuleManager is already defined
    require 'msf/core/module_manager/cache'
    require 'msf/core/module_manager/loading'
    require 'msf/core/module_manager/module_paths'
    require 'msf/core/module_manager/module_sets'
    require 'msf/core/module_manager/reloading'

    include Msf::ModuleManager::Cache
    include Msf::ModuleManager::Loading
    include Msf::ModuleManager::ModulePaths
    include Msf::ModuleManager::ModuleSets
    include Msf::ModuleManager::Reloading

    #
    # CONSTANTS
    #

    # Maps module type directory to its module type.
    TYPE_BY_DIRECTORY = Msf::Modules::Loader::Base::DIRECTORY_BY_TYPE.invert

    # Overrides the module set method for adding a module so that some extra steps can be taken to subscribe the module
    # and notify the event dispatcher.
    #
    # @param (see Msf::ModuleSet#add_module)
    # @return (see Msf::ModuleSet#add_module)
    def add_module(mod, name, file_paths)
      # Call {Msf::ModuleSet#add_module} with same arguments
      dup = super

      # Automatically subscribe a wrapper around this module to the necessary
      # event providers based on whatever events it wishes to receive.  We
      # only do this if we are the module manager instance, as individual
      # module sets need not subscribe.
      auto_subscribe_module(dup)

      # Notify the framework that a module was loaded
      framework.events.on_module_load(name, dup)

      dup
    end

    # Creates a module instance using the supplied reference name.
    #
    # @param [String] name a module reference name.  It may optionally be prefixed with a "<type>/", in which case the
    #   module will be created from the {Msf::ModuleSet} for the given <type>.
    # @return (see Msf::ModuleSet#create)
    def create(name)
      # Check to see if it has a module type prefix.  If it does,
      # try to load it from the specific module set for that type.
      names = name.split(File::SEPARATOR)
      potential_type_or_directory = names.first

      # if first name is a type
      if Msf::Modules::Loader::Base::DIRECTORY_BY_TYPE.has_key? potential_type_or_directory
        type = potential_type_or_directory
      # if first name is a type directory
      else
        type = TYPE_BY_DIRECTORY[potential_type_or_directory]
      end

      if type
        module_set = module_set_by_type[type]

        module_reference_name = names[1 .. -1].join(File::SEPARATOR)
        module_set.create(module_reference_name)
      # Otherwise, just try to load it by name.
      else
        super
      end
    end


    # @param [Msf::Framework] framework The framework for which this instance is managing the modules.
    # @param [Array<String>] types List of module types to load.  Defaults to all module types in {Msf::MODULE_TYPES}.
    def initialize(framework, types=Msf::MODULE_TYPES)
      #
      # defaults
      #

      self.module_info_by_path = {}
      self.enablement_by_type = {}
      self.module_load_error_by_path = {}
      self.module_paths = []
      self.module_set_by_type = {}

      #
      # from arguments
      #

      self.framework = framework

      types.each { |type|
        init_module_set(type)
      }

      super(nil)
    end

    protected

    # This method automatically subscribes a module to whatever event providers it wishes to monitor.  This can be used
    # to allow modules to automatically # execute or perform other tasks when certain events occur.  For instance, when
    # a new host is detected, other aux modules may wish to run such that they can collect more information about the
    # host that was detected.
    #
    # @param [Class] mod a Msf::Module subclass
    # @return [void]
    def auto_subscribe_module(mod)
      # If auto-subscribe has been disabled
      if (framework.datastore['DisableAutoSubscribe'] and
          framework.datastore['DisableAutoSubscribe'] =~ /^(y|1|t)/)
        return
      end

      # If auto-subscription is enabled (which it is by default), figure out
      # if it subscribes to any particular interfaces.
      inst = nil

      #
      # Exploit event subscriber check
      #
      if (mod.include?(Msf::ExploitEvent) == true)
        framework.events.add_exploit_subscriber((inst) ? inst : (inst = mod.new))
      end

      #
      # Session event subscriber check
      #
      if (mod.include?(Msf::SessionEvent) == true)
        framework.events.add_session_subscriber((inst) ? inst : (inst = mod.new))
      end
    end
  end
end
