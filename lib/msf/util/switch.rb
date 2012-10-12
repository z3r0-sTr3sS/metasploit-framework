#!/usr/bin/env ruby

require 'find'
require 'fileutils'

module Msf
	module Util

		class SvnSwitchConfig

			SEP = File::SEPARATOR
			GITHUB_SVN = 'https://github.com/rapid7/metasploit-framework'

			attr_reader :i, :new_svn_checkout, :new_source

			def initialize(i=nil)
				@i = (i || rand(2**16))
				@new_svn_checkout = github_svn_checkout_target
				@new_source = GITHUB_SVN
			end

			def msfbase
				base = __FILE__
				while File.symlink?(base)
					base = File.expand_path(File.readlink(base), File.dirname(base))
				end
				pwd = File.dirname(base)
				File.expand_path(File.join(pwd, "..", "..", ".."))
			end

			def github_svn_checkout_target
				@new_svn_checkout ||= File.join(msfbase, "msf-github-#{@i}")
			end

			def svn_binary
				res = %x|which 'svn'|
				return res.chomp
			end

			def svn_version
				res = %x|#{svn_binary} --version|
				res =~ /version (1\.[0-9\.]+)/
				return $1
			end

			def checkout_cmd
				cmd = [svn_binary]
				cmd += ["checkout", "--non-recursive"]
				cmd << self.new_source
				cmd << self.new_svn_checkout
			end

			def cleanup_cmd
				cmd = [svn_binary]
				cmd += ["cleanup"]
				cmd << self.new_svn_checkout
			end

			def cleanup_current_cmd
				cmd = [svn_binary]
				cmd += ["cleanup"]
				cmd << self.msfbase
			end

			def stage_cmd
				cmd = [svn_binary]
				cmd << "update"
				cmd << "--non-recursive"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def update_cmd
				cmd = [svn_binary]
				cmd << "update"
				cmd << "--set-depth"
				cmd << "infinity"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def info_cmd
				cmd = [svn_binary]
				cmd << "info"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def revert_cmd
				cmd = [svn_binary]
				cmd << "revert"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def untracked_files_list
				File.join(self.new_svn_checkout, "msf-svn-untracked.txt")
			end

			def status_current_cmd
				cmd = [svn_binary]
				cmd << "status"
				cmd << self.msfbase
			end

		end

		class SvnSwitch

			attr_reader :config

			def initialize
				@config = SvnSwitchConfig.new
			end

			# Pass args as a *array to protect against spaces
			def system(arg)
				raise ArgumentError unless arg.kind_of? Symbol
				raise ArgumentError unless arg.to_s =~ /_cmd$/
				raise ArgumentError unless @config.respond_to? arg
				cmd = @config.send arg
				# $stderr.puts "[!] #{cmd.join(' ')}"
				::Kernel.system(*cmd)
			end

			def delete_new_svn_checkout
				FileUtils.rm_rf self.config.new_svn_checkout
			end

			def create_untracked_files_list
				fname = self.config.untracked_files_list
				res = %x|#{self.config.svn_binary} status '#{self.config.msfbase}' > '#{fname}'|
				return fname
			end

		end

	end
end

