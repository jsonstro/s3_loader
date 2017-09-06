#!/usr/bin/env ruby
# encoding: utf-8

# Written by Josh Sonstroem (jsonstro@ucsc.edu) for UCSC AWS Project
# Version: 0.1.2

require 'aws-sdk'
require 'base64'
require 'digest'
require 'digest/sha2'
require 'json'
require 'optparse'
require 'openssl'
require 'rubygems'
require 'yaml'

# Load config
dir = File.dirname(__FILE__)
CNF="#{dir}/s3_loader.yaml"
CONF=YAML.load_file(CNF)

# Set AWS config file locations
HOME = File.expand_path('~')
AWS_CREDENTIALS="#{HOME}/.aws/credentials"
AWS_CONFIG = "#{HOME}/.aws/config"

# The number of seconds of time to request a session token to be valid for...
ses_exp = 900

# Default decryption algorithm and initialization vector
iv = nil
alg = "AES-256-CBC"

# Defaults
options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: #{__FILE__} COMMAND OBJECT BUCKET (CONTEXT) [OPTIONS] [MFA]"
  opt.separator  ""
  opt.separator  "COMMANDS"
  opt.separator  "  csd  -> Use Client-Side Decryption of KEY in BUCKET as OBJECT using CERT"
  opt.separator  "  ssd  -> Use Server-Side Decryption of KEY in BUCKET as OBJECT using CERT"
  opt.separator  "  kms  -> Use KMS Decryption of OBJECT in BUCKET as KEY"
  opt.separator  ""
  opt.separator  " OBJECT    -> REQUIRED Desired posix path to the decrypted local OBJECT"
  opt.separator  " BUCKET    -> REQUIRED Name of s3 BUCKET to download the encrypted object from, default can be set in #{CNF}"
  opt.separator  "(CONTEXT)  -> OPTIONAL Comma-separated list of 'key=value' pairs to add as decryption context - KMS ONLY!"
  opt.separator  ""
  opt.separator  " * --> Configure defaults for OPTIONS and MFA in config file: #{CNF}"
  opt.separator  ""
  opt.separator  "OPTIONS"
  opt.on("-c","--cert CERT","Posix path to PEM-format RSA Key or AES256 Cipher to use for decryption") do |cert|
    options[:cert] = cert
  end
  opt.on("-p","--profile PROFILE","Retreive creds from #{AWS_CREDENTIALS} as PROFILE, default is 'default'") do |profile|
    options[:profile] = profile
  end
  opt.on("-k","--key KEY","Name or KEY of the remote object in s3, default is the filename of the OBJECT") do |key|
    options[:key] = key
  end
  opt.on("-z","--region REGION","AWS Region you'd like to use, default is 'us-west-2'") do |region|
    options[:region] = region
  end
  opt.on("-r","--rsa","Enable client-side RSA decryption, default is 'AES256'") do |rsa|
    options[:rsa] = true
  end
  opt.on("-m","--kms","Use amazon KMS for key management of server-side AES256 decryption, default is 'false'") do |kms|
    options[:kms] = true
  end
  opt.on("-n","--envelope","Enable envelope decryption under KMS, default is 'false'") do |envelope|
    options[:envelope] = true
  end
  opt.on("-o","--output","If enabled will output the decrypted content as STDOUT") do |output|
    options[:output] = true
  end
  opt.separator  ""
  opt.separator  "MFA"
  opt.on("-s","--serial SERIAL","Serial number of your MFA device, looks like 'arn:aws:iam::1234567890:mfa/userid'") do |serial|
    options[:serial] = serial
  end
  opt.on("-t","--token TOKEN","Temporary token from your MFA device, will prompt you if no option") do |token|
    options[:token] = token
  end
  opt.separator  ""
  opt.separator  "HELP"
  opt.on("-h","--help","This help") do
    puts opt_parser
    exit
  end
end

opt_parser.parse!

# Check for valid mode
if( ARGV[0].nil? || ARGV[0] == '' ) then
  print "ERROR --> Decryption mode required! COMMAND must be 'csd', 'ssd' or 'kms'\n"
  puts opt_parser
  exit
end

# Check for name of OBJECT to download
path_to_object = ARGV[1]
if path_to_object.nil? then
  print "ERROR --> Path to local OBJECT required\n"
  puts opt_parser
  exit
end

# Handle moving decryption context to ARGV[3]
if ARGV[2] =~ /.*\=.*/ then
  ARGV[3] = ARGV[2]
  ARGV[2] = nil
end

# Check that BUCKET is filled in
bucket_name = ARGV[2] || CONF['bucket']
if bucket_name.nil? then
  print "ERROR --> BUCKET name required\n"
  puts opt_parser
  exit
elsif ARGV[2].nil? then
  ARGV[2] = "#{bucket_name}"
end

# Verify we have a cert if cse mode or sse-c requested
cert_to_use = options[:cert] || CONF['cert']
if(cert_to_use.nil? && ARGV[0] == "cse") then
  #if not options[:kms] then
    print "ERROR --> Path to CERT required [-c] for Client-side, use Server-side or KMS [-m] for managed certs.\n"
    puts opt_parser
    exit
  #end
end

# Which profile to get creds  from in ~/.aws/credentials? default is 'default'
prof = options[:profile] || CONF['profile']
if prof.nil? then
  print "ERROR --> Credentials error, reading profile #{prof} from #{AWS_CREDENTIALS}\n"
  puts opt_parser
  exit
end

# Read in the ~/.aws/config for profile specified above
toggle = false
if File.exist?(AWS_CONFIG) then
  File.foreach(AWS_CONFIG) do |line|
    if(line =~ /\[.*#{prof}\]/ || toggle) then
      toggle = true
      if(line =~ /^mfa_serial/ && CONF['mfa_serial'].nil?) then
        CONF['mfa_serial'] = line.split("=").last.strip
        #puts "Found MFA serial: #{CONF['mfa_serial']}"
      end
      if(line =~ /^region/ && CONF['region'].nil?) then
        CONF['region'] = line.split("=").last.strip
        #puts "Found region: #{CONF['region']}"
      end
      if(line =~ /^role_arn/ && CONF['role_arn'].nil?) then
        CONF['role_arn'] = line.split("=").last.strip
        #puts "Found role_arn: #{CONF['role_arn']}"
      end
      if(line =~ /^source_profile/ && CONF['source_profile'].nil?) then
        CONF['source_profile'] = line.split("=").last.strip
        #puts "Found role_arn: #{CONF['role_arn']}"
        prof = CONF['source_profile']
      end
      if line =~ /^\n/ then
        toggle = false
        break
      end
    end
  end
end
credentials = Aws::SharedCredentials.new(profile_name: "#{prof}")

# Setup the remote object name
key_for_obj = options[:key] || File.basename(path_to_object)

# Configure default region for s3 clients
AWS_REGION = options[:region] || CONF['region'] # default is 'us-west-2'

# MFA Serial: Default is none, looks like "arn:aws:iam::1234567890:mfa/userid"
AWS_MFA_SERIAL = options[:serial] || CONF['mfa_serial']
unless(AWS_MFA_SERIAL == '' || AWS_MFA_SERIAL.nil?) then
  userid = AWS_MFA_SERIAL.split("/").last
else
  # For some reason not using MFA, no userid to set :(
  userid = "#{env['USER']}"
end

# Using RSA format for client-side? Default is false
FRSA = options[:rsa] || CONF['rsa']

# Using KMS for key management, if so set kms_key_id? Default is false
KMS = options[:kms] || CONF['kms']

# Configure the STS session (MFA token) info then make some credentials based on 'em
session = ''
creds = ''
sessionfile = ".aws_session"
newsession = true
unless(AWS_MFA_SERIAL == '' || AWS_MFA_SERIAL.nil?) then
  # Startup a new STS client to configure an AWS session
  sts = Aws::STS::Client.new(region: AWS_REGION, credentials: credentials)
  unless CONF['role_arn'].nil? then
    # We get here if we have role switching enabled
    if File.exist?(sessionfile) then
      # Check for age of token
      fileage = Time.now - File.mtime(sessionfile)
      filesec = fileage.to_i
      if filesec < ses_exp then
        # Use the temp creds
        newsession = false
      else
        # Cleanup!
        File.delete(sessionfile)
      end
    end
    if newsession then
      # We don't have a current session file
      if options[:token].nil? then
        print "--> Please input your current MFA token code:"
        AWS_MFA_TOKEN = STDIN.gets.chomp
      else
        AWS_MFA_TOKEN = options[:token]
      end
      session = sts.assume_role(role_arn: CONF['role_arn'], role_session_name: "#{userid}", duration_seconds: ses_exp, external_id: "UCSCAWS", serial_number: AWS_MFA_SERIAL, token_code: AWS_MFA_TOKEN)
      creds = Aws::Credentials.new(session.credentials.access_key_id, session.credentials.secret_access_key, session.credentials.session_token)
      token = session.to_h.to_json
      File.open(sessionfile, 'wb') { |file| file.write(token) }
    else
      # We got a current session file
      token = File.open(sessionfile, "rb") { |file| file.read }
      json = JSON.parse(token)
      access_key_id = json.fetch("credentials").fetch("access_key_id")
      secret_access_key = json.fetch("credentials").fetch("secret_access_key")
      session_token = json.fetch("credentials").fetch("session_token")
      creds = Aws::Credentials.new(access_key_id, secret_access_key, session_token)
    end
  else
    # Otherwise we assume user is defined in the VPC directly
    if options[:token].nil? then
      print "--> Please input your current MFA token code:"
      AWS_MFA_TOKEN = STDIN.gets.chomp
    else
      AWS_MFA_TOKEN = options[:token]
    end
    session = sts.get_session_token(duration_seconds: ses_exp, serial_number: AWS_MFA_SERIAL, token_code: AWS_MFA_TOKEN)
    creds = Aws::Credentials.new(session.credentials.access_key_id, session.credentials.secret_access_key, session.credentials.session_token)
  end
else
  # If we get here we don't have MFA configured for some reason, maybe using host-role?
  creds = Aws::Credentials.new(region: AWS_REGION, credentials: credentials)
end

# Configure Server-side decryption mode for use below
sse_mode = ''
if ARGV[0] != "csd" then
  if KMS == true then
    # If we have kms flag set then managing keys in AWS
    sse_mode = 'aws:kms'
  else
    sse_mode = 'AES256' # default
  end
  puts "--> Using #{sse_mode} for server-side decryption requests"
end

# Also configure default kms_key_id and if using envelope decryption
ENVENC = options[:envelope] || CONF['envelope']

# This next bit checks if we have provided decryption context and puts it into a hash if so
context = ''
enc_con = ''
enc_hash = Hash.new
enc_keys = ''

# Did we get decryption context specified?
unless ARGV[3].nil? then
  unless(KMS == true || ARGV[0] == "kms") then
    # If our mode is not KMS or we don't have the KMS flag something is amiss
    print "ERROR --> Decryption context requires use of KMS\n"
    exit
  end
  comma = false
  if ARGV[3] =~ /\,/ then
    # If we have a comma we are dealing with multiple contexts
    comma = true
  end
  context = ARGV[3]
  # Transform the decryption context key=value pairs into json-style '"key" => "value"' pairs
  if comma == true then
    # If we see a comma split the pairs first
    context = context.split(",")
  end
  # Cast contents as an Array
  context = Array(context)
  context.each do |kv|
    # For each key=value pair convert them into hash
    k = kv.split("=").first
    v = kv.split("=").last
    if enc_hash.empty? then
      # First entry, new hash!
      enc_hash = enc_hash.merge!("#{k}" => "#{v}")
      enc_keys = "#{k}"
    else
      # Repeat entry, update existing hash instead
      temp = Hash.new
      temp = temp.merge!("#{k}" => "#{v}")
      enc_hash.merge!(temp)
      enc_keys = "#{enc_keys}, #{k}"
    end
  end
  enc_con = enc_hash
  print "--> Using decryption context: #{enc_con}\n"
end

# Test the number of ARGS, make sure its 3 or more
if ARGV.length < 3 then
  print "ERROR --> requires 3 ARGS: COMMAND, OBJECT, BUCKET\n"
  puts opt_parser
  exit
end

# Main body of the program here
case ARGV[0]
when "csd"
  # Doing Client-side decryption
  cert=''
  ctype=''
  # Check if we are using RSA or AES for Client-side and read in the cert or cipher
  if FRSA then
    ctype="RSA"
    cert = OpenSSL::PKey::RSA.new File.read(cert_to_use)
  else
    ctype="AES"
    cert = File.read(cert_to_use)
  end
  begin
    # startup a new client-side decryption client for download
    client = Aws::S3::Encryption::Client.new(credentials: creds, encryption_key: cert)
    unless options[:output] then
      # We are writing object to filesystem
      client.get_object(bucket:bucket_name, key:key_for_obj, response_target:path_to_object)
      puts "--> Client-Side #{ctype} Decryption of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}"
    else
      # output option is set, so we won't write the object to filesystem but rather to STDOUT
      resp = client.get_object(bucket:bucket_name, key:key_for_obj)
      puts "--> Client-Side #{ctype} Decryption to STDOUT of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}"
      body = resp.body.read
      puts "#{body}"
    end
  rescue Aws::S3::Errors::ServiceError => e
    "CSD - Something went wrong: #{e}"
  end
# We get here when COMMAND is 'ssd'
when "ssd"
  # Straight SSD, we are not using the KMS service
  # Server-side only supports AES
  ctype="AES"
  begin
    cert=''
    # startup a new s3 client for download
    client = Aws::S3::Client.new(credentials: creds)

    # Check to see if user specified a local AES cipher to use, if so using sse-c give cert and md5
    unless cert_to_use.nil? then
      cert = File.read(cert_to_use)
      # Generate an MD5 of the cert for verification
      cmd5 = Digest::MD5.base64digest(cert)
      unless options[:output] then
        client.get_object(bucket:bucket_name, key:key_for_obj, response_target:path_to_object, sse_customer_algorithm: "AES256", sse_customer_key:cert, sse_customer_key_md5: cmd5)
        puts "--> Server-Side #{ctype} Decryption of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}\n"
      else
        resp = client.get_object(bucket:bucket_name, key:key_for_obj, sse_customer_algorithm: "AES256", sse_customer_key:cert, sse_customer_key_md5: cmd5)
        puts "--> Server-Side #{ctype} Decryption to STDOUT of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}\n"
        body = resp.body.read
        puts "#{body}"
      end
    else
      # Using sse-s3 or sse-kms for managing keys
      unless options[:output] then
        client.get_object(bucket:bucket_name, key:key_for_obj, response_target:path_to_object)
        puts "--> Server-Side #{ctype} Decryption of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
      else
        resp = client.get_object(bucket:bucket_name, key:key_for_obj)
        puts "--> Server-Side #{ctype} Decryption to STDOUT of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        body = resp.body.read
        puts "#{body}"
      end
    end
  rescue Aws::S3::Errors::ServiceError => e
    "SSD - Error encountered: #{e}"
  end
when "kms"
  # We are using KMS for managing our keys, smart!
  # KMS only supports AES
  ctype="AES"
  begin
    print "--> Using SSE-KMS, KMS is managing our ssd keys\n"
    # Startup a new KMS client for decryption
    kms = Aws::KMS::Client.new(credentials: creds)

    # Are we using envelope decryption?
    unless ENVENC then
      # Envelope encrpytion is false :(

      ### If additional layer of encrpytion was enabled in client uncomment this and comment other client line below
      ### client = Aws::S3::Encryption::Client.new(credentials: creds, kms_key_id: KMS_KEY_ID, kms_client: kms)

      # Startup a new s3 client
      client = Aws::S3::Client.new(credentials: creds)

      # Are we using decryption context?
      if enc_con == '' then
        # Not using decryption context, get the object
        obj = client.get_object(bucket:bucket_name, key:key_for_obj)
        data = obj.body.read
        # decrypt the blob with the KMS master key
        resp = kms.decrypt(ciphertext_blob: "#{data}")
        secret = resp.plaintext
        unless options[:output] then
          File.open(path_to_object, 'wb') { |file| file.write("#{secret}") }
          puts "--> AWS-KMS Server-Side #{ctype} Decryption of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          puts "--> AWS-KMS Server-Side #{ctype} Decryption to STDOUT of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
          puts "#{secret}"
        end
      else
        # Using decryption context -- smart!
        obj = client.get_object(bucket:bucket_name, key:key_for_obj)
        data = obj.body.read
        resp = kms.decrypt(ciphertext_blob: "#{data}", encryption_context: enc_con )
        secret = resp.plaintext
        unless options[:output] then
          File.open(path_to_object, 'wb') { |file| file.write("#{secret}") }
          puts "--> AWS-KMS Server-Side #{ctype} Decryption of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with decryption context\n"
        else
          puts "--> AWS-KMS Server-Side #{ctype} Decryption to STDOUT of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with decryption context\n"
          puts "#{secret}"
        end
      end
    else
      # Envelope decryption is true!
      print "--> Using KMS envelope decryption\n"
      envelope = ''
      ciphertext_blob=''
      suffix = '.ekey'

      ### If additional layer of encrpytion was enabled in client uncomment this and comment other client line below
      ### client = Aws::S3::Encryption::Client.new(credentials: creds, kms_key_id: KMS_KEY_ID, kms_client: kms, envelope_location: :instruction_file, instruction_file_suffix: suffix)

      # Fetch the envelope, startup a new s3 client
      s3 = Aws::S3::Client.new(credentials: creds)
      resp = s3.get_object(bucket:bucket_name, key: "#{key_for_obj}#{suffix}")
      envelope = resp.body.read

      # If outputing to STDOUT configure our display var
      unless options[:output] then
        outs = " "
      else
        outs = " to STDOUT "
      end

      # Decrypt the envelope (object decryption key) with KMS
      deckey = ''
      if enc_con == '' then
        deckey = kms.decrypt(ciphertext_blob: envelope)
        puts "--> AWS-KMS #{ctype} Envelope Decryption#{outs}using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}"
      else
        deckey = kms.decrypt(ciphertext_blob: envelope, encryption_context: enc_con)
        puts "--> AWS-KMS #{ctype} Envelope Decryption#{outs}using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with decryption context\n"
      end

      # Download then decrypt our object with the object key we just decrypted above
      client = Aws::S3::Encryption::Client.new(encryption_key: deckey.plaintext, client: s3)
      obj = client.get_object(bucket:bucket_name, key:key_for_obj)
      secret = obj.body.read
      unless options[:output] then
        File.open(path_to_object, 'wb') { |file| file.write("#{secret}") }
      else
        puts "#{secret}"
      end
    end
  rescue Aws::S3::Errors::ServiceError => e
    "SSD-KMS Error encountered: #{e}"
  end
else
  # We get here if no actual known command was supplied
  print "ERROR --> '#{ARGV[0]}' is an unknown command, try one of 'csd', 'ssd' or 'kms' modes\n"
  puts opt_parser
end
