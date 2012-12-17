#!/usr/bin/env ruby

# History with colors and e-mail addresses (respecting .mailmap):
# git log --pretty=format:"%C(white)%ad %C(yellow)%h %Cblue'%aN' <%aE> %Cgreen%f%Creset" --date=short

class GitLogLine < Struct.new(:date, :hash, :author, :message)
end

@history = `git log --pretty=format:"%ad %h '%aN' %f" --date=short --date-order`
@recent_history = []
@commits_by_author = {}

cutoff_date = "2012-06-16"

@history.each_line do |line|
	parsed_line = line.match(/^([^\s+]+)\s(.{7,})\s'(.*)'\s(.*)[\r\n]*$/)
	break if cutoff_date == parsed_line[1]
	@recent_history << GitLogLine.new(*parsed_line[1,4])
end

@recent_history.each do |logline|
	@commits_by_author[logline.author] ||= []
	@commits_by_author[logline.author] << logline.message
end

puts "Commits since #{cutoff_date}"
puts "-" * 50

@commits_by_author.sort_by {|k,v| v.size}.reverse.each do |k,v|
	puts "%-25s %3d" % [k,v.size]
end

