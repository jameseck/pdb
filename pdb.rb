#!/usr/bin/env ruby

require 'optparse'
require 'puppetdb'
require 'yaml'
require 'pp'

default_options = {
  :debug        => false,
  :list_only    => false,
  :order        => 'name',
  :ssh_opts     => '-A -t -Y',
  :ssh_user     => 'root',
  :mgmt_ip_fact => 'ipaddress',
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

facts_include = []
facts_criteria = {}

option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($0)} [options] hostname1 hostname2 hostname3regex"
  opts.on("-f", "--fact FACT", "Fact to query for (specify fact name or name=value") do |v|
    if v.include? "=" then
      name,val=v.split("=")
      facts_criteria[name] = val
    else
      facts_include << v
    end
  end
  opts.on("-l", "--ssh_user USER", "User for SSH (default: root)") do |v|
    @options[:ssh_user] = v
  end
  opts.on("-L", "--list-only", "List nodes only, don't try to ssh") do
    @options[:list_only] = true
  end
  opts.on("-o", "--order name,ip", [ :name, :ip], "Sort order for node list (ip,name). Default: name") do |v|
    @options[:order] = v
  end
  opts.on("-s", "--ssh-options OPTIONS", "Options for SSH (default: -A -t -Y)") do |v|
    @options[:ssh_opts] = v
  end
  opts.on("--ssl_cert FILE", "SSL certificate file to connect to puppetdb") do |v|
    options[:ssl_cert] = v
  end
  opts.on("--ssl_key FILE", "SSL key file to connect to puppetdb") do |v|
    options[:ssl_key] = v
  end
  opts.on("--ssl_ca FILE", "SSL ca file to connect to puppetdb") do |v|
    options[:ssl_ca] = v
  end
  opts.on("-d", "--debug", "Show additional debug logging") do |v|
    options[:debug] = true
  end
  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit 1
  end
end

option_parser.parse!

PP.pp facts_criteria
PP.pp facts_include

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

def printnodes(nodes_array)
  max_length = nodes_array.max_by{ |a| a['name'].length }['name'].length
  nodes_array.each do |n|
    printf "# %-#{max_length}s  %-12s\n", n['name'], n['ip']
  end
end

if ARGV.length >= 1
  hostname = ARGV[0]
else
  puts option_parser
  puts "\n"
  puts "ERROR: You must provide a hostname\n"
  exit 1
end

if @options[:debug]
  require 'pp'
  PP.pp @options
  puts "ARGV:\n"
  puts ARGV
end

@options[:ssl_key] = File.expand_path(@options[:ssl_key])
@options[:ssl_cert] = File.expand_path(@options[:ssl_cert])
@options[:ssl_ca] = File.expand_path(@options[:ssl_ca])
validate_ssl_opt :ssl_key
validate_ssl_opt :ssl_cert
validate_ssl_opt :ssl_ca


pdb_client_config = {
  'server' => @options[:server_url],
  'pem' => {
    'key'     => @options[:ssl_key],
    'cert'    => @options[:ssl_cert],
    'ca_file' => @options[:ssl_ca],
  }
}

# A hash to gather node and fact together
nodes_array = []

# something like:
# ["and",
#   ["or",
#       ["=", "name", "ipaddress"],
#       ["=", "name", "osfamily"]
#   ],
#   ["in", "certname",
#     ["extract", "certname", ["select-facts",
#       ["and",
#         ["=", "name", "osfamily"],
#         ["=", "value", "RedHat"]
#       ]
#     ]]
#   ]
# ]

client = PuppetDB::Client.new(pdb_client_config)
response = client.request( 'facts', [:and, [:'~', 'certname', hostname], ['=', 'name', @options[:mgmt_ip_fact] ] ] )
response.data.each do |n|
  nodes_array << { 'name' => n['certname'], 'ip' => n['value'] }
end

nodes_array = nodes_array.sort_by{ |hash| hash[@options[:order]] }

if nodes_array.empty? then
  puts "No results found.\n"
  exit 0
end

if @options[:list_only] then
  printnodes nodes_array
  exit 0
end

if nodes_array.length > 1 then
  puts "Found nodes:\n"
  puts "\n"

  nodes_array.each_with_index do |n, index|
    print "#{index+1}: #{n['name']} - #{n['ip']}\n"
  end
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

if real_node then
  puts "SSHing to #{real_node['name']} - #{real_node['ip']}\n"
  exec "ssh #{@options[:ssh_opts]} #{@options[:ssh_user]}@#{real_node['ip']}\n"
end
