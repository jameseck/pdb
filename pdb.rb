#!/usr/bin/env ruby

require 'optparse'
require 'puppetdb'
require 'yaml'
require 'json'
require 'net/https'
require 'uri'
require 'pp'

default_options = {
  :debug        => false,
  :list_only    => false,
  :order        => 'fqdn',
  :ssh_opts     => '-A -t -Y',
  :ssh_user     => nil,
  :threads      => 5,
  :mgmt_ip_fact => 'ipaddress',
  :fact_and_or  => 'and',
  :command      => false,
}

@options = default_options

config_file = "#{Dir.home}/.pdb/pdb.yaml"

# If there is a config file, merge the options with the default options
# Note that in the config file you can specify the options as "ssh_key" rather than ":ssh_key"
if File.exists? config_file then
  config_file_options = YAML.load_file(config_file)
  unless config_file_options == nil then
    config_file_options.each { |k,v| @options[k.to_sym] = v }
  end
end

facts_include = [ @options[:mgmt_ip_fact], ]
facts_criteria = {}


option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($0)} [options] hostnameregex"
  opts.on("-c", "--command COMMAND", "Run command on all matching hosts") do |c|
    @options[:command] = c
  end
  opts.on("-f", "--fact FACT", "Fact criteria to query for (specify fact name or name=value") do |f|
    f.split(',').each do |v|
      next if v == nil
      # Support all v3 api operators
      factmatch = v.scan(/^(.*?)(<=|>=|=|~|<|>)(.*?)$/)
      puts "factmatch: #{factmatch}\n" if ARGV.include? '-d'
      if factmatch.empty?
        facts_include << v
        next
      end
      facts_criteria[factmatch[0][0]] ||= {}
      facts_criteria[factmatch[0][0]]['op'] = factmatch[0][1]
      facts_criteria[factmatch[0][0]]['value'] = factmatch[0][2]
    end
  end
  opts.on("--fact-and", "Multiple fact criteria are ANDed (default)") do |v|
    @options[:fact_and_or] = 'and'
  end
  opts.on("--fact-or", "Multiple fact criteria are ORed") do |v|
    @options[:fact_and_or] = 'or'
  end
  opts.on("-t", "--threads NUM", "Number of threads to use for SSH commands") do |v|
    @options[:threads] = v
  end
  opts.on("-l", "--ssh_user USER", "User for SSH (default: whatever your ssh client will use)") do |v|
    @options[:ssh_user] = v
  end
  opts.on("-L", "--list-only", "List nodes only, don't try to ssh") do
    @options[:list_only] = true
  end
  opts.on("-o", "--order FIELD", "Sort order for node list (fqdn,fact). Default: fqdn") do |v|
    @options[:order] = v
  end
  opts.on("-s", "--ssh-options OPTIONS", "Options for SSH (default: -A -t -Y)") do |v|
    @options[:ssh_opts] = v
  end
  opts.on("--ssl_cert FILE", "SSL certificate file to connect to puppetdb") do |v|
    @options[:ssl_cert] = v
  end
  opts.on("--ssl_key FILE", "SSL key file to connect to puppetdb") do |v|
    @options[:ssl_key] = v
  end
  opts.on("--ssl_ca FILE", "SSL ca file to connect to puppetdb") do |v|
    @options[:ssl_ca] = v
  end
  opts.on("-d", "--debug", "Show additional debug logging") do |v|
    @options[:debug] = true
  end
  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit 1
  end
end

option_parser.parse!

cols = ([ 'fqdn' ] << facts_include).flatten
# Some validation

def validate_ssl_opt (opt)
  unless @options.has_key? opt
    puts "missing '#{opt}' configuration\n"
    exit 1
  else
    unless File.exists? @options[opt]
      puts "file '#{@options[opt]}' specified in '#{opt}' option does not exist or is inaccessible\n"
      exit 1
    end
  end
end

def print_matches (cols, matches, index=false)
  columns = {}
  if index then
    columns['index'] = matches.length.to_s.length
    columns['index'] = 5 if columns['index'] < 5
    cols =([ 'index' ] << cols).flatten
  end

  cols.each do |c|
    matches.each do |m|
      next if not m.has_key? c
      columns[c] ||= 0
      columns[c] = c.length if c.length > columns[c]
      columns[c] = m[c].length if m[c].length > columns[c]
    end
  end

  output = ""
  header = ""
  cols.each do |col|
    next if not columns.has_key? col
    output << sprintf("%-#{columns[col]}s " % col)
    header << sprintf("%-#{columns[col]}s " % ('-' * columns[col]))
  end
  output << "\n#{header}\n"
  node_index = 1
  matches.each do |m|
    if index then
      output << sprintf("%-#{columns['index']}s " % node_index)
    end
    cols.each do |col|
      next if col == 'index'
      output << " " * (columns[col].to_i+1) if not m.has_key? col
      next if m[col] == nil
      m[col] = m[col].gsub "\n", "\\n" # Bit hacky but we need to get rid of real newlines
      output << sprintf("%-#{columns[col]}s " % m[col])
    end
    output << "\n"
    node_index += 1
  end
  output
end

if ARGV.length >= 1
  hostname = ARGV[0]
else
  hostname = '.*'
end

if @options[:debug]
  PP.pp @options
  puts "ARGV: #{ARGV}\n"
end

@options[:ssl_key] = File.expand_path(@options[:ssl_key])
@options[:ssl_cert] = File.expand_path(@options[:ssl_cert])
@options[:ssl_ca] = File.expand_path(@options[:ssl_ca])
validate_ssl_opt :ssl_key
validate_ssl_opt :ssl_cert
validate_ssl_opt :ssl_ca

if @options[:debug] then
  puts "fact_include: #{facts_include}\n"
  puts "fact_criteria: #{facts_criteria}\n"
end

# build up the query string
query = "[ \"and\",\n"
query << "  [ \"~\", \"certname\", \"#{hostname}\" ],\n"
query << "  [ \"or\",\n"

facts_inc = []
facts_include.each do |f|
  facts_inc << "    [ \"=\", \"name\", \"#{f}\" ]\n"
end
query << facts_inc.join(",")
query << "  ]\n"
query << " ,[\"#{@options[:fact_and_or]}\"\n" if not facts_criteria.empty?
facts_criteria.each do |k,v|
  query << "   ,[ \"in\", \"certname\",\n"
  query << "      [ \"extract\", \"certname\", [ \"select-facts\",\n"
  query << "        [ \"and\",\n"
  query << "          [ \"=\", \"name\", \"#{k}\" ],\n"
  query << "          [ \"#{v['op']}\", \"value\", \"#{v['value']}\" ]\n"
  query << "        ]\n"
  query << "      ]]\n"
  query << "    ]\n"
end
query << "  ]\n" if not facts_criteria.empty?
query << "]\n"

puts "query: #{query}\n" if @options[:debug]

uri = URI.parse("#{@options[:server_url]}/v3/facts?query=#{URI.encode(query)}")
key = File.read(File.expand_path(@options[:ssl_key]))
cert = File.read(File.expand_path(@options[:ssl_cert]))
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.cert = OpenSSL::X509::Certificate.new(cert)
http.key = OpenSSL::PKey::RSA.new(key)
http.ca_file = File.expand_path(@options[:ssl_ca])
http.verify_mode = OpenSSL::SSL::VERIFY_PEER

request = Net::HTTP::Get.new(uri.request_uri)
response = http.request(request)
results_array = JSON.parse(response.body)

results_hash = {}
results_array.each do |a|
  results_hash[a['certname']] ||= {}
  results_hash[a['certname']][a['name']] = a['value']
end
nodes_array = []
results_hash.each do |k,v|
  nodes_array << { 'fqdn' => k }.merge(v)
end


if nodes_array.empty? then
  puts "No results found.\n"
  exit 0
end

if nodes_array.find {|h| h.member? @options[:order] } then
  nodes_array = nodes_array.sort_by{ |hash| hash[@options[:order]] || '' }
else
  puts "Invalid order field '#{@options[:order]}' specified\n"
  exit 1
end

puts "matching nodes: #{nodes_array}\n" if @options[:debug]

if @options[:list_only] then
  puts print_matches(cols, nodes_array, false)
  exit 0
end

if @options[:command] then
  inv = { 'all' => { 'hosts' => nodes_array.map { |x| x[@options[:mgmt_ip_fact]] } } }
  invfile = "#{Dir.home}/.pdb/tmpinventorylist"
  File.open(invfile, 'w') { |f| f.write("#!/bin/sh\nprintf '#{inv.to_json}\n'\n") }
  File.chmod(0700, invfile)
  ansible_command = "ansible all -i \"#{invfile}\""
  ansible_command << " -a \"#{@options[:command]}\""
  ansible_command << " -f #{@options[:threads]}"
  ansible_command << " -u #{@options[:ssh_user]}" if @options[:ssh_user]
  puts "ansible command: #{ansible_command}\n" if @options[:debug]
  system(ansible_command)
  File.delete invfile unless @options[:debug]
  exit 0
end

if nodes_array.length > 1 then
  puts "Found nodes:\n"
  puts "\n"
  puts print_matches(cols, nodes_array, true)
  puts "\n"
  puts "Please pick a node to SSH to: "
  num = STDIN.gets.chomp().to_i
  if not num.between?(1, nodes_array.length) then
    puts "Try picking a number that exists...\n"
    exit 1
  end
  real_node = nodes_array[num-1]
else
  real_node = nodes_array[0]
end

node_fqdn = real_node['fqdn']
node_ip = real_node[@options[:mgmt_ip_fact]]

if real_node then
  puts "SSHing to #{node_fqdn} - #{node_ip}\n"
  exec "ssh #{@options[:ssh_opts]} #{@options[:ssh_user]}@#{node_ip}\n"
end
