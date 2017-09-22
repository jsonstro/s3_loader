#
# Cookbook:: s3_loader_examples
# Recipe:: kms_master_key_decrypt
#

# Include the aws-sdk
chef_gem 'aws-sdk' do
    compile_time true
end

require 'aws-sdk'
require 'aws-sdk-core'
require 'yaml'

# Required for windows cert (mis)handling
Aws.use_bundled_cert!

stack = search("aws_opsworks_stack").first
region = stack['region']

# Create the S3 client object for using in the SDK
node.default[:s3][:client] = Aws::S3::Client.new(region: region)

# Create the KMS client object for using in the SDK
kms = Aws::KMS::Client.new(region: region)

# Fetch the secrets file from S3 bucket to memory
# ....decrypt it using KMS
# ....then parse the resultant YAML plaintext into the secrets hash

resp = node[:s3][:client].get_object( bucket: node[:secrets][:s3][:bucket],
				      key:    node[:secrets][:s3][:key])
content = kms.decrypt(ciphertext_blob: resp.body)
node.default[:secrets][:content] = YAML.load(content.plaintext)

