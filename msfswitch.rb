#!/usr/bin/env ruby

# TODO: Allow the user to specify the msfbase, might be useful
# TODO: More or less verbosity? Some steps are silent, others are verbose.
# TODO: Need to test on basically everything, since this is a one-way trip
# TODO: Consider an Are You Sure confirmation.

start_time = Time.now.utc

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))

require 'msf/util/svn'
unless Msf::Util::SVN.root =~ /^http.+metasploit\.com/
	$stdout.puts "[-] This is not an anonymous SVN checkout, aborting."
	exit 1
end

require 'msf/util/switch'

@svn_switcher = Msf::Util::SvnSwitch.new

$stdout.puts "[*]"
$stdout.puts "[*] Switching Metasploit Framework to the official GitHub SVN repo."
$stdout.puts "[*] This procedure will take several minutes."
$stdout.puts "[*]"
$stdout.puts ""
temp_checkout = @svn_switcher.new_svn_checkout
$stdout.puts "[*] Prepping current checkout #{@svn_switcher.config.msfbase}"
unless @svn_switcher.system :cleanup_current_cmd
	$stdout.puts "[-] Error with svn cleanup, aborting!"
	exit 2
end

$stdout.puts "[*] Creating temporary checkout at #{temp_checkout}"
@svn_switcher.system :checkout_cmd
$stdout.puts "[*] Staging the svn update."
@svn_switcher.system :stage_cmd
$stdout.puts "[*] Updating contents."
@svn_switcher.system :update_cmd
$stdout.puts "[*] Preserving locally changed files and directories"
@svn_switcher.backup_local_files
$stdout.puts "[*] Replacing the current checkout with the new checkout"
@svn_switcher.copy_new_checkout
$stdout.puts "[*] Cleaning up"
@svn_switcher.system :cleanup_current_cmd
@svn_switcher.system :revert_gemfile_current_cmd
@svn_switcher.cleanup_empty_dirs { |f| $stdout.puts "[*]  Removing empty dir #{f}" }
$stdout.puts "[*] Deleting the temporary Git checkout."
@svn_switcher.delete_new_svn_checkout
$stdout.puts "[+] Conversion complete!"
@svn_switcher.status_current_cmd

end_time = Time.now.utc - start_time
$stdout.puts "[*] Time elapsed: %0.2fm" % (end_time / 60.0)
