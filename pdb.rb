#!/usr/bin/env ruby

require 'optparse'
require 'yaml'
require 'json'
require 'net/https'
require 'uri'
require 'tempfile'
require 'pp'

fqdn = `hostname -f`.chomp

default_options = {
  :ansible_module  => 'shell',
  :ansible_args    => [],
  :ansible_opts    => [],
  :ansible_env     => [],
  :command         => false,
  :debug           => false,
  :fact_and_or     => 'and',
  :include_facts   => true,
  :list_fact_names => false,
  :list_only       => false,
  :mgmt_ip_fact    => 'ipaddress',
  :order           => 'fqdn',
  :remote_user     => 'root',
  :ssh_opts        => '-A -t -Y',
  :ssh_user        => nil,
  :ssh_fqdn         => nil,
  :ssl_ca          => '/var/lib/puppet/ssl/certs/ca_crt.pem',
  :ssl_cert        => "/var/lib/puppet/ssl/certs/#{fqdn}.pem",
  :ssl_key         => "/var/lib/puppet/ssl/private_keys/#{fqdn}.pem",
  :use_sudo        => true,
  :threads         => 5,
  :pdbversion      => "3",
  :configdir       => "#{Dir.home}/.pdb"
}

@options = default_options

def exit_prog(exit_code=0)
  exit exit_code
end

# Set some empty arrays
options_tmp_facts = []
nodes_array = []
cols = []
list_fact_names = []

option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($0)} [options] [hostregex] [hostregex] ..."
  opts.on("-a", "--ansible-module-args OPTS", "Pass module arguments to ansible") do |a|
    @options[:ansible_opts] << a
  end
  opts.on("-A", "--ansible-args ARG", "Additional Ansible arguments. (Default/Current: #{default_options[:ansible_args]})") do |v|
    @options[:ansible_args] << v
  end
  opts.on("-c", "--command COMMAND", "Run command on all matching hosts using ansible") do |c|
    unless system("which ansible > /dev/null 2>&1")
      puts "ansible was not found.\n"
      puts "To run commands with this script, you need to install ansible.\n"
      exit_prog 1
    end
    @options[:command] = c
  end
  opts.on("-d", "--[no-]debug", "Whether to show additional debug logging. Default/Current: #{default_options[:debug]}") do |v|
    @options[:debug] = v
  end
  opts.on("-e", "--ansible-env VAR", "Ansible environment variables. Default/Current: #{default_options[:ansible_env]}") do |v|
    @options[:ansible_env] << v
  end
  opts.on("-f", "--fact FACT", "Fact criteria to query for. (specify fact name or name=value)") do |f|
    options_tmp_facts << f
  end
  opts.on("--fact-and", "Multiple fact criteria are ANDed. Default") do |v|
    @options[:fact_and_or] = 'and'
  end
  opts.on("--fact-or", "Multiple fact criteria are ORed.") do |v|
    @options[:fact_and_or] = 'or'
  end
  opts.on("-i", "--[no-]include-facts", "Include facts in output that were used in criteria. Default/Current: #{default_options[:include_facts]}") do |v|
    @options[:include_facts] = v
  end
  opts.on("-l", "--ssh_user USER", "User for SSH. Default/Current: whatever your ssh client will use") do |v|
    @options[:ssh_user] = v
  end
  opts.on("--list-fact-names", "Display a list of all known facts in PuppetDB") do |v|
    @options[:list_fact_names] = true
  end
  opts.on("-L", "--[no-]list-only", "List nodes only, don't try to ssh. Default/Current: #{default_options[:list_only]}") do |v|
    @options[:list_only] = v
  end
  opts.on("-m", "--ansible-module MODULE", "Specify which module to use for ansible command Default/Current: #{default_options[:ansible_module]}") do |m|
    @options[:ansible_module] = m
  end
  opts.on("-o", "--order FIELD", "Sort order for node list (fqdn,fact). Default/Current: fqdn") do |v|
    @options[:order] = v
  end
  opts.on("-r", "--remote_user USER", "User to become - only used by ansible. Default/Current: #{default_options[:remote_user]}") do |v|
    @options[:remote_user] = v
  end
  opts.on("-s", "--ssh-options OPTIONS", "Options for SSH (Default/Current: #{default_options[:ssh_opts]}") do |v|
    @options[:ssh_opts] = v
  end
  opts.on("--ssh-fqdn", "Boolean option to SSH to FQDN rather than IP (Default/Current: #{default_options[:ssh_fqdn]}") do |v|
    @options[:ssh_fqdn] = v
  end
  opts.on("--ssl_cert FILE", "SSL certificate file to connect to puppetdb. Default/Current: #{default_options[:ssl_cert]}") do |v|
    @options[:ssl_cert] = v
  end
  opts.on("--ssl_key FILE", "SSL key file to connect to puppetdb. Default/Current: #{default_options[:ssl_key]}") do |v|
    @options[:ssl_key] = v
  end
  opts.on("--ssl_ca FILE", "SSL ca file to connect to puppetdb. Default/Current: #{default_options[:ssl_ca]}") do |v|
    @options[:ssl_ca] = v
  end
  opts.on("-t", "--threads NUM", "Number of threads to use for SSH commands. Default/Current: #{default_options[:threads]}") do |v|
    @options[:threads] = v
  end
  opts.on("--[no-]use-sudo", "Whether to use sudo on the remote host - only used by ansible. Default/Current: #{default_options[:use_sudo]}") do |v|
    @options[:use_sudo] = v
  end
  opts.on("--configdir FILE", "Config directory - for use with multiple puppet db's. Current setting: #{default_options[:configdir]}") do |v|
    @options[:configdir] = v
  end
  opts.on("--pdbversion [3|5]", "Define the pdb version to set endpoints - [3 | 5] #{default_options[:pdbversion]}") do |v|
    @options[:pdbversion] = v
  end
  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit_prog 1
  end
end

option_parser.parse!

# Setup all options
config_dir = "#{@options[:configdir]}"

unless File.exists? config_dir
  File.mkdir config_dir
  File.chmod 0700, config_dir
end

config_file = "#{config_dir}/pdb.yaml"

def set_endpoint
  if @options[:pdbversion] == "3"
    @endpoint = "/v3"
  elsif @options[:pdbversion] == "5"
    @endpoint = "/pdb/query/v4"
  else
    puts "#{@options[:pdbversion]} - Is not a valid choice for PDB version - use 3 (default) or 5"
    exit_prog 1
  end
end

def fact_names(list_fact_names)

  set_endpoint

  puts "list_fact_names before #{list_fact_names.count}"

  uri = URI.parse("#{@options[:server_url]}#{@endpoint}/fact-names")
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

  data = JSON.parse(response.body)
  data.each {|a| list_fact_names.push(a)}

  puts "list_fact_names after #{list_fact_names.count}"

end

def validate_ssl_opt (opt)
  unless @options.has_key? opt
    puts "missing '#{opt}' configuration\n"
    exit_prog 1
  else
    unless File.exists? @options[opt]
      puts "file '#{@options[opt]}' specified in '#{opt}' option does not exist or is inaccessible\n"
      exit_prog 1
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
      next unless m.has_key? c
      columns[c] ||= 0
      columns[c] = c.length if c.length > columns[c]
      columns[c] = m[c].length if m[c].length > columns[c]
    end
  end

  output = ""
  header = ""
  cols.uniq.each do |col|
    next unless columns.has_key? col
    output << sprintf("%-#{columns[col]}s " % col)
    header << sprintf("%-#{columns[col]}s " % ('-' * columns[col]))
  end
  output << "\n#{header}\n"
  node_index = 1
  matches.each do |m|
    if index then
      output << sprintf("%-#{columns['index']}s " % node_index)
    end
    cols.uniq.each do |col|
      next if col == 'index'
      output << " " * (columns[col].to_i+1) unless m.has_key? col
      next if m[col] == nil
      m[col] = m[col].gsub "\n", "\\n" # Bit hacky but we need to get rid of real newlines
      output << sprintf("%-#{columns[col]}s " % m[col])
    end
    output << "\n"
    node_index += 1
  end
  output
end

def pdb_main (options_tmp_facts, nodes_array, cols, pdb)
  facts_include = [ @options[:mgmt_ip_fact] ]
  facts_criteria = {}

  set_endpoint

  if ARGV.length >= 1
    hostnames = ARGV
  else
    hostnames = [ '.*' ]
  end

  if @options[:debug]
    STDERR.puts "\e[31mOptions:"
    opts = PP.pp(@options, "")
    STDERR.puts opts
    STDERR.puts "ARGV: #{ARGV}\n\e[0m"
  end

  @options[:ssl_key] = File.expand_path(@options[:ssl_key])
  @options[:ssl_cert] = File.expand_path(@options[:ssl_cert])
  @options[:ssl_ca] = File.expand_path(@options[:ssl_ca])
  validate_ssl_opt :ssl_key
  validate_ssl_opt :ssl_cert
  validate_ssl_opt :ssl_ca


  options_tmp_facts.each do |f|
    f.split(',').each do |v|
      next if v == nil
      # Support all v3 api operators
      factmatch = v.scan(/^(.*?)(<=|>=|=|~|<|>)(.*?)$/)
      STDERR.puts "\e[31mfactmatch: #{factmatch}\n\e[0m" if @options[:debug]
      if factmatch.empty?
        facts_include << v
        next
      end
      facts_include << factmatch[0][0] if @options[:include_facts] and not facts_include.include? factmatch[0][0]
      facts_criteria[factmatch[0][0]] ||= {}
      facts_criteria[factmatch[0][0]]['op'] = factmatch[0][1]
      facts_criteria[factmatch[0][0]]['value'] = factmatch[0][2]
    end
  end

  # cols.push ([ 'fqdn', 'ssh_to', 'pdb' ] << facts_include).flatten
  cols.push ([ 'fqdn', 'ssh_to', 'pdb' ] << facts_include).flatten

  if @options[:debug] then
    STDERR.puts "\e[31mfact_include: #{facts_include}\n"
    STDERR.puts "fact_criteria: #{facts_criteria}\n\e[0m"
  end

  # build up the query string
  query = "[ \"and\",\n"
  query << "  [ \"or\",\n"
  hosts_q = []
  hostnames.each do |h|
    hosts_q << "    [ \"~\", \"certname\", \"#{h}\" ]\n"
  end
  query << hosts_q.join(',')
  query << "  ],\n"
  query << "  [ \"or\",\n"

  facts_inc = []
  facts_include.each do |f|
    facts_inc << "    [ \"=\", \"name\", \"#{f}\" ]\n"
  end
  query << facts_inc.join(",")
  query << "  ]\n"
  query << " ,[\"#{@options[:fact_and_or]}\"\n" unless facts_criteria.empty?
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
  query << "  ]\n" unless facts_criteria.empty?
  query << "]\n"

  STDERR.puts "\e[31mquery: #{query}\n\e[0m" if @options[:debug]

  uri = URI.parse("#{@options[:server_url]}#{@endpoint}/facts?query=#{URI.encode(query)}")
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
    results_hash[a['certname']]['pdb'] = pdb
    unless a['name'] == @options[:mgmt_ip_fact]
      results_hash[a['certname']][a['name']] = a['value']
    else
      if @options[:list_only]
        results_hash[a['certname']][a['name']] = a['value']
      end
      results_hash[a['certname']]['ssh_to'] = a['value']
    end
    unless @options[:ssh_fqdn].nil?
      results_hash[a['certname']]['ssh_to'] = a['certname']
    end
  end
  results_hash.each do |k,v|
    nodes_array << { 'fqdn' => k }.merge(v)
  end
end

def print_fact_names(list_fact_names)
  puts "Facts available\n#{list_fact_names.uniq.join("\n")}"
  exit_prog 0
end

if File.exists? config_file then
  config_file_options = YAML.load_file(config_file)
  unless config_file_options == nil then
    config_file_options.keys.each do |pdb|
      config_file_options[pdb].each do |k, v|
        @options[k.to_sym] = v
      end
      if @options[:list_fact_names]
        fact_names(list_fact_names)
      else
        pdb_main(options_tmp_facts, nodes_array, cols, pdb)
      end
    end
    if @options[:list_fact_names]
      print_fact_names(list_fact_names)
    end
  end
end


if nodes_array.empty? then
  puts "No results found.\n"
  exit_prog 0
end

if nodes_array.find {|h| h.member? @options[:order] } then
  nodes_array = nodes_array.sort_by{ |hash| hash[@options[:order]] || '' }
else
  puts "Invalid order field '#{@options[:order]}' specified\n"
  exit_prog 1
end

STDERR.puts "\e[31mmatching nodes: #{nodes_array}\n\e[0m" if @options[:debug]

#if @options[:list_fact_names] then
#  puts config_file_options.keys
#  puts "In if block = #{list_fact_names.count}"
#  exit_prog 0
#end

if @options[:list_only] then
  puts print_matches(cols, nodes_array, true)
  exit_prog 0
end

if @options[:command] or not @options[:ansible_args].empty? or not @options[:ansible_opts].empty? then
  if @options[:ssh_fqdn].nil?
    inv = { 'all' => { 'hosts' => nodes_array.map { |x| x[@options[:mgmt_ip_fact]] } } }
  else
    inv = { 'all' => { 'hosts' => nodes_array.map { |x| x["fqdn"] } } }
  end
  tmp_inventory_file = Tempfile.new('pdb_inventory', "#{@options[:configdir]}")
  tmp_inventory_file.write "#!/bin/sh\nprintf '#{inv.to_json}\n'\n"
  tmp_inventory_file.close
  ObjectSpace.undefine_finalizer(tmp_inventory_file) if @options[:debug]
  File.chmod(0700, tmp_inventory_file.path)
  ansible_command = "ansible all -i \"#{tmp_inventory_file.path}\""
  ansible_command << " -f #{@options[:threads]}"
  ansible_command << " -m #{@options[:ansible_module]}" unless @options[:ansible_module].empty?
  ansible_command << " -a \"#{@options[:command]}\"" if @options[:command]
  ansible_command << " -u #{@options[:ssh_user]}" if @options[:ssh_user]
  ansible_command << " --become " if @options[:use_sudo]
  ansible_command << " --become-user #{@options[:remote_user]}" if @options[:remote_user] and @options[:use_sudo]
  @options[:ansible_opts].each { |e| ansible_command << " -a \"#{e}\"" }
  @options[:ansible_args].each { |e| ansible_command << " #{e}" }
  @options[:ansible_env].each { |e| ansible_command << " -e \"#{e}\"" }
  STDERR.puts "\e[31mansible command: #{ansible_command}\n\e[0m" if @options[:debug]
  system(ansible_command)
  STDERR.puts "\e[31mAnsible exit code: #{$?}\n\e[0m" if @options[:debug]
  exit_prog 0
end

if nodes_array.length > 1 then
  puts nodes_array
  puts "Found nodes:\n"
  puts "\n"
  puts print_matches(cols, nodes_array, true)
  puts "\n"
  puts "Please pick a node to SSH to: "
  num = STDIN.gets.chomp().to_i
  unless num.between?(1, nodes_array.length) then
    puts "Try picking a number that exists...\n"
    exit_prog 1
  end
  real_node = nodes_array[num-1]
else
  real_node = nodes_array[0]
end

if real_node then
  node_fqdn = real_node['fqdn']
  node_ip = real_node['ssh_to']
  puts "SSHing to #{node_fqdn} - #{node_ip}\n"
  if @options[:ssh_fqdn].nil?
    ssh_to = node_ip
  else
    ssh_to = node_fqdn
  end
  if @options[:ssh_user]
    useratip = "#{@options[:ssh_user]}@#{ssh_to}"
  else
    useratip = ssh_to
  end
  cmd = "ssh #{@options[:ssh_opts]} #{useratip}"
  STDERR.puts "\e[31mssh cmd: #{cmd}\n\e[0m" if @options[:debug]
  exec(cmd)
end
