#
# Author:: Joshua Timberman <joshua@getchef.com
# Copyright (c) 2014, Chef Software, Inc. <legal@getchef.com>
#
# Portions from https://github.com/computology/packagecloud-cookbook:
# Copyright (c) 2014, Computology, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'uri'
require 'pathname'

module ChefServerIngredient
  module Helpers
    # FIXME: (jtimberman) make this data we can change / use without
    # having to update the library code (e.g., if we create new
    # add-ons, or change any of these in the future).
    def chef_server_ctl_command(pkg)
      ctl_cmds = {
        'chef-server-core' => 'chef-server-ctl',
        'opscode-manage' => 'opscode-manage-ctl',
        'opscode-push-jobs-server' => 'opscode-push-jobs-server-ctl',
        'opscode-reporting' => 'opscode-reporting-ctl',
        'opscode-analytics' => 'opscode-analytics-ctl',
        'chef-sync' => 'chef-sync-ctl'
      }
      ctl_cmds[pkg]
    end
  end
end

Chef::Recipe.send(:include, ChefServerIngredient::Helpers)
Chef::Resource.send(:include, ChefServerIngredient::Helpers)
Chef::Provider.send(:include, ChefServerIngredient::Helpers)

# From https://github.com/computology/packagecloud-cookbook/blob/master/libraries/helper.rb
# FIXME: (jtimberman) Use the packagecloud_repo resource
# instead, when it can either set the codename, or we publish
# packages to "trusty"
module PackageCloud
  module Helper
    require 'net/https'
    require 'openssl'

 def ssl_config
if (!ENV['SSL_CERT_FILE'] || !File.exist?(ENV['SSL_CERT_FILE'])) &&
(!ENV['SSL_CERT_DIR'] || !File.exist?(ENV['SSL_CERT_DIR']))
# Attempt to copy over from other environment variables or well-known
# locations. But seriously, just set the environment variables!
common_ca_file_locations = [
ENV['CA_FILE'],
'/usr/local/lib/ssl/certs/ca-certificates.crt',
'/usr/local/ssl/certs/ca-certificates.crt',
'/usr/local/share/curl/curl-ca-bundle.crt',
'/usr/local/etc/openssl/cert.pem',
'/opt/local/lib/ssl/certs/ca-certificates.crt',
'/opt/local/ssl/certs/ca-certificates.crt',
'/opt/local/share/curl/curl-ca-bundle.crt',
'/opt/local/etc/openssl/cert.pem',
'/usr/lib/ssl/certs/ca-certificates.crt',
'/usr/ssl/certs/ca-certificates.crt',
'/usr/share/curl/curl-ca-bundle.crt',
'/etc/ssl/certs/ca-certificates.crt',
'/etc/pki/tls/cert.pem',
'/etc/pki/CA/cacert.pem',
'C:\Windows\curl-ca-bundle.crt',
'C:\Windows\ca-bundle.crt',
'C:\Windows\cacert.pem',
'./curl-ca-bundle.crt',
'./cacert.pem',
'~/.cacert.pem'
]
common_ca_path_locations = [
ENV['CA_PATH'],
'/usr/local/lib/ssl/certs',
'/usr/local/ssl/certs',
'/opt/local/lib/ssl/certs',
'/opt/local/ssl/certs',
'/usr/lib/ssl/certs',
'/usr/ssl/certs',
'/etc/ssl/certs',
'/etc/pki/tls/certs'
]
ENV['SSL_CERT_FILE'] = nil
ENV['SSL_CERT_DIR'] = nil
for location in common_ca_file_locations
if location && File.exist?(location)
ENV['SSL_CERT_FILE'] = File.expand_path(location)
break
end
end
unless ENV['SSL_CERT_FILE']
for location in common_ca_path_locations
if location && File.exist?(location)
ENV['SSL_CERT_DIR'] = File.expand_path(location)
break
end
end
end
end
end
def print_ssl_config
openssl_dir = OpenSSL::X509::DEFAULT_CERT_AREA
puts "%s: %s" % [OpenSSL::OPENSSL_VERSION, openssl_dir]
[OpenSSL::X509::DEFAULT_CERT_DIR_ENV, OpenSSL::X509::DEFAULT_CERT_FILE_ENV].each do |key|
puts "%s=%s" % [key, ENV[key].to_s.inspect]
end
return openssl_dir
end
def file_log(message)
f=File.open('/tmp/packagecloud.log','a+')
f.write "#{message}\n"
f.close
end
def get(uri, params)
file_log "begin"
uri.query = URI.encode_www_form(params)
req = Net::HTTP::Get.new(uri.request_uri)
req.basic_auth uri.user, uri.password if uri.user
file_log "Uri:#{uri.hostname}:#{uri.port}"
ssl_config
file_log print_ssl_config
ENV['SSL_CERT_FILE'] = '/opt/rightscale/sandbox/ssl/certs/ca-bundle.crt'
raise "SSL Cert Missing" unless File.exists?(ENV['SSL_CERT_FILE'])
http = Net::HTTP.new(uri.hostname, uri.port)
if uri.port == 443
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.cert_store = OpenSSL::X509::Store.new
http.cert_store.set_default_paths
options_mask = OpenSSL::SSL::OP_NO_SSLv2 + OpenSSL::SSL::OP_NO_SSLv3
#http.ssl_options = options_mask
http.cert_store.add_file('/etc/pki/tls/certs/ca-bundle.crt')
else
http.use_ssl = false
end
file_log "starting response"
resp = http.start { |h| h.request(req) }
case resp
when Net::HTTPSuccess
resp
else
raise resp.inspect
end
end
    def post(uri, params)
      req           = Net::HTTP::Post.new(uri.request_uri)
      req.form_data = params

      req.basic_auth uri.user, uri.password if uri.user

      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = true

      resp = http.start { |h|  h.request(req) }

      case resp
      when Net::HTTPSuccess
        resp
      else
        raise resp.inspect
      end
    end
  end
end
