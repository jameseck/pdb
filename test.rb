#!/usr/bin/env ruby

require 'net/https'
require 'uri'
require 'json'
require 'yaml'
require 'pp'

query = URI.encode '
["and",
  ["or",
    ["=", "name", "ipaddress"],
    ["=", "name", "osfamily"]
  ],
  ["in", "certname",
    ["extract", "certname", ["select-facts",
                              ["and",
                                ["=", "name", "osfamily"],
                                ["=", "value", "RedHat"]
                              ]]]
  ]
]
'

config_file = "#{Dir.home}/.pdb/pdb.yaml"
@options = {}

# If there is a config file, merge the options with the default options
# Note that in the config file you can specify the options as "ssh_key" rather than ":ssh_key"
if File.exists? config_file then
  config_file_options = YAML.load_file(config_file)
  unless config_file_options == nil then
    config_file_options.each { |k,v| @options[k.to_sym] = v }
  end
end

uri = URI.parse("#{@options[:server_url]}/v3/facts?query=#{query}")
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


PP.pp results_hash
