#!/usr/bin/env ruby

system("git checkout master")
git_branches = %x{ git branch -v | awk '{print $1,$2}'}
remote = "origin"

i = 0
hits = 0
git_branches.each_line do |line|
	next if line == "* master\n"
	branch, hash = line.strip.split
	contains_data = %x{git branch --contains #{hash}}
	i += 1
	if contains_data.include? "* master\n"
		puts %Q{>>> git push #{remote} :#{branch}}
		hits += 1 
	else
		puts "#{branch} has not been merged to master."
	end
end

puts "[+] Will delete #{hits} of #{i} stale branches."
