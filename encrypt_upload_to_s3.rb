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

# Load this app's config
dir = File.dirname(__FILE__)
CNF = "#{dir}/s3_loader.yaml"
conf = YAML.load_file(CNF)

# Set AWS config file locations
HOME = File.expand_path('~')
AWS_CREDENTIALS="#{HOME}/.aws/credentials"
AWS_CONFIG = "#{HOME}/.aws/config"

# The number of seconds of time to request a session token to be valid for...
ses_exp = 900

# Default encryption algorithm, initialization vector, and rsa key-size
iv = nil
alg = "AES-256-CBC"
rsasize = 4096

# Setup option parser
options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: #{__FILE__} COMMAND OBJECT BUCKET (CONTEXT) [OPTIONS] [MFA]"
  opt.separator  ""
  opt.separator  "COMMANDS"
  opt.separator  "  cse  -> Use Client-Side Encryption of OBJECT in BUCKET as KEY using CERT"
  opt.separator  "  sse  -> Use Server-Side Encryption of OBJECT in BUCKET as KEY using CERT"
  opt.separator  "  kms  -> Use KMS Encryption of OBJECT in BUCKET as KEY"
  opt.separator  ""
  opt.separator  " OBJECT    -> REQUIRED Posix path to the local OBJECT to encrypt"
  opt.separator  " BUCKET    -> REQUIRED Name of s3 BUCKET to upload encrypted object into, default can be set in #{CNF}"
  opt.separator  "(CONTEXT)  -> OPTIONAL Comma deliniated list of 'key=value' pairs to add as encryption context - 'kms' ONLY!"
  opt.separator  ""
  opt.separator  " * --> Configure defaults for OPTIONS and MFA in config file: #{CNF}"
  opt.separator  " * --> Configure specific defaults for an AWS profile in a config file named 'PROFILE.yaml'"
  opt.separator  ""
  opt.separator  "OPTIONS"
  opt.on("-c","--cert CERT","Posix path to PEM-format RSA Public Key or AES256 Cipher to use for encryption") do |cert|
    options[:cert] = cert
  end
  opt.on("-p","--profile PROFILE","Retreive creds from ~/.aws/credentials as PROFILE, default is 'default'") do |profile|
    options[:profile] = profile
  end
  opt.on("-k","--key KEY","Name to use as KEY for object in s3, default is filename of object source") do |key|
    options[:key] = key
  end
  opt.on("-z","--region REGION","AWS Region you'd like to use, default is 'us-west-2'") do |region|
    options[:region] = region
  end
  opt.on("-r","--rsa","Enable client-side RSA Encryption, default is 'AES256'") do |rsa|
    options[:rsa] = true
  end
  opt.on("-m","--kms [kms_key_id]","Use amazon KMS for key management of server-side AES256 encryption using kms_key_id as key, default is 'false'") do |kms|
    options[:kms] = true
    options[:kms_key_id] = kms
  end
  opt.on("-n","--envelope","Enable envelope encryption under KMS, default is 'false'") do |envelope|
    options[:envelope] = true
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
  opt.separator  "GENERATE"
  opt.on("-g","--generate TYPE,[NAME]", Array,"Generate a new TYPE 'KMS' master key or 'RSA' #{rsasize} cert or 'AES' #{alg} cipher called NAME in current directory") do |generate|
    options[:generate] = generate
  end
  opt.separator  ""
  opt.separator  "HELP"
  opt.on("-h","--help","This help") do
    puts opt_parser
    exit
  end
  opt.on("-v","--verbose","Enables verbose output for debugging purposes") do |verbose|
    options[:verbose] = true
  end
end

# This next section parses all the options and config stuff
opt_parser.parse!

# Check for valid mode
if( ARGV[0].nil? || ARGV[0] == '' ) then
  print "ERROR --> Encryption mode required! COMMAND must be 'cse', 'sse' or 'kms'\n"
  puts opt_parser
  exit
end

# Get path to OBJECT to encrypt and upload
path_to_object = ARGV[1]
if path_to_object.nil? then
  print "ERROR --> Path to local OBJECT required!\n"
  puts opt_parser
  exit
end

# Check is ARGV2 is actually encryption context, e.g. contains an '=', if so then move to argv3
if ARGV[2] =~ /.*\=.*/ then
  ARGV[3] = ARGV[2]
  ARGV[2] = nil
end

# Check PWD for yaml for specific profile
prof = options[:profile] || conf['profile']
CNF2 = "#{dir}/#{prof}.yaml"
if File.exists?(CNF2) then
  print "--> Found specific YAML config for profile: #{prof}.yaml\n"
  conf.merge!(YAML.load_file(CNF2))
end

# Setup s3 bucket to upload into either from ARGV2 or conf
bucket_name = ARGV[2] || conf['bucket']
if bucket_name.nil? then
  print "ERROR --> BUCKET name required! Add to CMD line or specify in #{conf}\n"
  puts opt_parser
  exit
elsif ARGV[2].nil? then
  # Be sure to set ARGV2 so our ARGV# check does not fail below
  ARGV[2] = "#{bucket_name}"
end

# Configure the certificate or cipher to use from option or conf
cert_to_use = options[:cert] || conf['cert']

# Which profile to use for creds from ~/.aws/credentials, default is 'default'
if prof.nil? then
  print "ERROR --> Credentials error, reading profile #{prof} from #{AWS_CREDENTIALS}\n"
  puts opt_parser
  exit
end

# Read in the ~/.aws/config for profile specified above
toggle = false
if File.exist?(AWS_CONFIG) then
  if options[:verbose] == true then
    print "[*** .aws/config '#{prof}' ***]\n"
  end
  File.foreach(AWS_CONFIG) do |line|
    if(line =~ /\[.*#{prof}\]/ || toggle) then
      toggle = true
      if(line =~ /^mfa_serial/ && conf['mfa_serial'].nil?) then
        conf['mfa_serial'] = line.split("=").last.strip
        if options[:verbose] == true then
          puts "v-> Found MFA serial: #{conf['mfa_serial']}"
        end
      end
      if(line =~ /^region/ && conf['region'].nil?) then
        conf['region'] = line.split("=").last.strip
        if options[:verbose] == true then
          puts "v-> Found region: #{conf['region']}"
        end
      end
      if(line =~ /^role_arn/ && conf['role_arn'].nil?) then
        conf['role_arn'] = line.split("=").last.strip
        if options[:verbose] == true then
          puts "v-> Found role_arn: #{conf['role_arn']}"
        end
      end
      if(line =~ /^source_profile/ && conf['source_profile'].nil?) then
        conf['source_profile'] = line.split("=").last.strip
        if options[:verbose] == true then
          puts "v-> Found source_profile: #{conf['source_profile']}"
        end
        prof = conf['source_profile']
      end
      if line =~ /^\n/ then
        toggle = false
        break
      end
    end
  end
end

# Generate new AWS shared credentials using specified profile
credentials = Aws::SharedCredentials.new(profile_name: "#{prof}")

# Configure remote filename for OBJECT if different or use basename as default
key_for_obj = options[:key] || File.basename(path_to_object)

# Configure default region from options or conf, default is 'us-west-2'
AWS_REGION = options[:region] || conf['region']
if( AWS_REGION == '' || AWS_REGION == nil ) then
  print "ERROR --> AWS_REGION not found in config or yaml"
  exit
end

# Configure MFA Serial which looks like "arn:aws:iam::1234567890:mfa/userid", default is none
AWS_MFA_SERIAL = options[:serial] || conf['mfa_serial']
unless(AWS_MFA_SERIAL == '' || AWS_MFA_SERIAL.nil?) then
  userid = AWS_MFA_SERIAL.split("/").last
else
  # For some reason not using MFA, no userid to set :(
  userid = "#{ENV['USER']}"
end

# Configure if using RSA format for client-side, default is false
FRSA = options[:rsa] || conf['rsa']

# Configure if using KMS for key management, default is false
KMS = options[:kms] || conf['kms'] # true/false

# Load our default KMS Master Key ID from the config or option
kms_key_id = options[:kms_key_id] || conf['kms_key_id']

# Configure the STS session (MFA token) info then make some credentials based on 'em
session = ''
creds = ''
sessionfile = ".aws_session"
newsession = true
unless(AWS_MFA_SERIAL == '' || AWS_MFA_SERIAL.nil?) then
  # Startup a new STS client to configure an AWS session
  sts = Aws::STS::Client.new(region: AWS_REGION, credentials: credentials)
  unless conf['role_arn'].nil? then
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
      session = sts.assume_role(role_arn: conf['role_arn'], role_session_name: "#{userid}", duration_seconds: ses_exp, external_id: "UCSCAWS", serial_number: AWS_MFA_SERIAL, token_code: AWS_MFA_TOKEN)
      creds = Aws::Credentials.new(session.credentials.access_key_id, session.credentials.secret_access_key, session.credentials.session_token)
      token = session.to_h.to_json
      File.open(sessionfile, 'wb') { |file| file.write(token) }
    else
      # We got a current session file, parse the keys out from json
      unless File.zero?(sessionfile) then
        token = File.open(sessionfile, "rb") { |file| file.read }
        json = JSON.parse(token)
        access_key_id = json.fetch("credentials").fetch("access_key_id")
        secret_access_key = json.fetch("credentials").fetch("secret_access_key")
        session_token = json.fetch("credentials").fetch("session_token")
        creds = Aws::Credentials.new(access_key_id, secret_access_key, session_token)
      else
        puts "ERROR --> .aws_session file exists but is empty, please delete from current directory"
        exit
      end
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
  # If we get here we don't have MFA configured for some reason, maybe have host-role?
  creds = Aws::Credentials.new(region: AWS_REGION, credentials: credentials)
end

# Configure Server-side encryption mode for use below
sse_mode = ''
if ARGV[0] != "cse" then
  if KMS == true then
    sse_mode = 'aws:kms'
  else
    sse_mode = 'AES256' # default
  end
  puts "--> Using #{sse_mode} for server-side encryption requests"
end

# Also configure default kms_key_id and if using envelope encrytion
ENVENC = options[:envelope] || conf['envelope'] # true/false

# This next bit checks if we have provided encryption context and puts it into a hash if so
context = ''
enc_con = ''
enc_hash = Hash.new
enc_keys = '' # Context keys get added to metadata of object

# Check if we specified encryption context
unless ARGV[3].nil? then
  # We have some sort of encryption context being asked for...
  unless ARGV[0] == "kms" then
    # Bail if we somehow made it here without KMS mode enabled
    print "ERROR --> Encryption context requires use of KMS mode!\n"
    exit
  end
  comma = false
  if ARGV[3] =~ /\,/ then
    comma = true
  end
  context = ARGV[3]
  # Transform the encryption context key=value pairs into json-style '"key" => "value"' pairs
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
  print "--> Using encryption context: #{enc_con}\n"
end

# Finally, verify we have right number of ARGS = 3
if ARGV.length < 3 then
  print "ERROR --> requires 3 ARGS: COMMAND, OBJECT, BUCKET\n"
  puts opt_parser
  exit
end

# If generating a new cert setup name and type from options array
gen = options[:generate] || []
cname="cert.pem"
certtype="" # RSA, AES, or KMS
if(gen != nil && gen.count == 2) then
  certtype = gen[0]
  cname = gen[1]
elsif(gen != nil && gen.count == 1) then
  certtype = gen[0]
end

# If type is set then we requested to generate a new RSA cert or AES cipher or KMS key below
if certtype == "RSA" then
  print "--> Please input passphrase for the RSA key or leave blank for none:"
  PASSWORD = STDIN.gets.chomp
  private_key = ''
  rsa_key = OpenSSL::PKey::RSA.new(rsasize)
  cipher =  OpenSSL::Cipher::Cipher.new('des3')
  unless PASSWORD == "" then
    # Generate the key with the supplied PASSWORD
    private_key = rsa_key.to_pem(cipher,PASSWORD)
  else
    private_key = rsa_key.to_pem
  end
  public_key = rsa_key.public_key.to_pem
  key_pair = private_key + public_key
  File.open("#{cname}", "wb") { |f| f.print key_pair }
  print "--> Generated new RSA key pair in PEM format as #{cname}\n"
  cert_to_use = "#{cname}"
elsif certtype == "AES" then
  # We use the AES 256 bit cipher-block chaining symetric encryption
  N = cname.split(".").first
  # We want a 256 bit key symetric key based on some passphrase
  digest = Digest::SHA256.new
  print "--> Please input passphrase for the AES Cipher or leave blank to generate a random key:"
  PASSWORD = STDIN.gets.chomp
  unless PASSWORD.nil? then
    # Create a 256bit digest from supplied passphrase
    digest.update(PASSWORD)
    key = digest.digest
  else
    # We just create a random key
    key = OpenSSL::Cipher::Cipher.new(alg).encrypt.random_key
  end
  File.open("#{N}.aes", "wb") { |f| f.print key }
  print "--> Generated a new AES Cipher as #{N}.aes, keep this private\n"
  cert_to_use = "#{N}.aes"
end

# Check if cert_to_use is still nil, bail if CSE is requested
if((cert_to_use.nil? || cert_to_use == '') && ARGV[0] == "cse") then
  print "ERROR --> Path to CERT required [-c] for Client-side, use Server-side or KMS [-m] for managed certs.\n"
  puts opt_parser
  exit
end

# S3 bucket public credentials check...
d = 0
clnt = Aws::S3::Client.new(credentials: creds)
rsp = clnt.get_bucket_acl(bucket: bucket_name)
if options[:verbose] == true then
  print "v-> BUCKET PERMS:\n"
end
rsp['grants'].each do | grantee |
  if options[:verbose] == true then
    puts "[*** Grant \##{d} ***]"
  end
  if(grantee['grantee']['display_name'] != '' && grantee['grantee']['display_name'] != nil && options[:verbose] == true) then
    puts "v----> Name:  #{grantee['grantee']['display_name']}" 
  end
  if options[:verbose] == true then
    puts "v----> Type:  #{grantee['grantee']['type']}"
    puts "v----> Perms: #{grantee['permission']}"
  end
  if(grantee['grantee']['uri'] != '' && grantee['grantee']['uri'] != nil)
    if options[:verbose] == true then
      puts "v----> URI:   #{grantee['grantee']['uri']}" 
    end
    if grantee['grantee']['uri'] =~ /.*AllUsers.*/ then
      puts "ERROR --> The S3 bucket '#{bucket_name}' has public permissions (#{grantee['permission']})"
      print "ABORTING!!!\n"
      exit
    end
  end
  d += 1
end

# Main part of program here
case ARGV[0]
when "cse"
  # We get here when command is 'cse', client-side encryption requested
  cert=''
  ctype=''
  begin
    # Read in the cert specified and rescue the OpenSSL errors
    if FRSA then
      # Format RSA set above, make sure key is not too small
      ctype="RSA"
      if File.size?(cert_to_use) < 512 then
        print "ERROR --> Did you mean to use AES rather than RSA encryption for CSE? If so, remove the '-r' option flag or check your cert"
        exit
      end
      cert = OpenSSL::PKey::RSA.new File.read(cert_to_use)
      if cert.private? then
        puts "WARNING --> Found private key in #{cert_to_use}, we only need a public key to encrypt with..."
      end
    else
      # Default format AES set above, make sure file is not too big
      ctype="AES"
      if File.size?(cert_to_use) > 512 then
        print "ERROR --> Did you mean to use RSA rather than AES encryption for CSE? If so, add the '-r' option flag or check your cipher"
        exit
      end
      cert = File.read(cert_to_use)
    end
  rescue OpenSSL::PKey::RSAError => e
    puts "CSE - Cipher or cert failure: #{e}"
  end
  begin
    # Open a new encryption client using cert from above
    client = Aws::S3::Encryption::Client.new(credentials: creds, encryption_key: cert)
    File.open(path_to_object, 'rb') do |file|
      # Put the file into s3 specifing key name and type in metadata
      client.put_object(bucket:bucket_name, key:key_for_obj, body:file, metadata: { "#{ctype}-encryption-key-name" => "#{cert_to_use}" })
      puts "--> Client-Side #{ctype} Encryption of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}\n"
    end
  rescue Aws::S3::Errors::ServiceError => e
    puts "CSE - Something went wrong: #{e}"
  end
when "sse"
  # We get here when COMMAND is 'sse', server-side encryption requested
  # Server-side only supports AES ciphers
  ctype="AES"
  begin
    # Start up a client
    client = Aws::S3::Client.new(credentials: creds)

    ### Note: additional layer of encryption available here via client if desired ###
    ### client = Aws::S3::Encryption::Client.new(credentials: creds, encryption_key: cert)

    File.open(path_to_object, 'rb') do |file|
      if sse_mode == "AES256" then
        # We are not using the KMS service, sadies :(
        unless cert_to_use.nil? then
          # Check to see if user specified a local AES cipher to use, if so using sse-c so put cert and md5
          print "--> Using SSE-C, we are managing sse keys\n"

          # Make sure we aren't accidentally supplying an RSA key
          if File.size?(cert_to_use) > 512 then
            print "ERROR --> RSA encryption is not valid type for SSE! Try CSE mode or check your cipher"
            exit
          end

          # Get the MD5 of the cipher for verification
          cert = File.read(cert_to_use)
          cmd5 = Digest::MD5.base64digest(cert)

          # Put up the object using the SSE-C customer key and MD5
          client.put_object(bucket:bucket_name, key:key_for_obj, body:file, metadata: { "#{ctype}-encryption-key-name" => "#{cert_to_use}" }, sse_customer_algorithm: "#{sse_mode}", sse_customer_key:cert, sse_customer_key_md5: cmd5)
          puts "--> Server-side #{ctype} encryption of #{path_to_object} using #{cert_to_use} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          # Nope, just using sse-s3, pop the object up there with no frills
          print "--> Using SSE-s3, s3 is managing our sse keys\n"
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", body:file)
          puts "--> Server-side #{ctype} encryption of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        end
      else
        # Using sse-kms -- plain 'ol master-key encryption
        print "--> Using SSE-KMS, KMS is managing our sse keys\n"
        unless cert_to_use.nil? then
          # Error out if we have a cert being specified and mode sse with a [-m] option flag
          puts "ERROR --> Can't use SSE-KMS (option '-m') with SSE-C client-managed server-side encryption (mode 'sse', option '-c')\n"
          exit
        end

        # Pop the object up there specifying the sse kms key id to the client
        client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, body:file)
        puts "--> Server-side #{ctype} encryption of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
      end
    end
  rescue Aws::S3::Errors::ServiceError => e
    puts "SSE (#{sse_mode}) - Error encountered: #{e}"
  end
when "kms"
  # We get here when command was 'kms', smart!
  ctype="AES"
  begin
    # Startup a new KMS client
    print "--> Using SSE-KMS, KMS is managing our sse keys\n"
    kms = Aws::KMS::Client.new(credentials: creds)

    # Check if master key was specified, if not or generate mode was KMS drop in...
    if(kms_key_id.nil? || certtype == "KMS") then
      print "--> *** ATTENTION: no KMS master key ID was specified! ***\n"
      print "----> Do you want to generate a new KMS master key or use existing?\n"
      print "----> Enter 'g' to generate a new or 's' to select existing from list: "
      RESP = STDIN.gets.chomp
      if(RESP != "g" && RESP != "s")
        # Error out if we didn't get 'g' or 's'
        puts "ERROR --> Unknown response: #{RESP} != (g|s), KMS master key ID is required to use KMS\n"
        exit
      elsif RESP == "g" then
        key_alias = ''
        if cname != "cert.pem" then
          unless cname =~ /^[a-zA-Z0-9\-\_]+$/ then
            puts "ERROR --> KMS key name '#{cname}' can only contain alpha-numeric characters and dashes"
            exit
          end
          key_alias = cname
        else
          key_alias = "#{bucket_name}-key"
        end
        # We are gonna generate a new KMS master key
        keyresp = kms.create_key(tags: [ { tag_key: "CreatedBy", tag_value: "#{userid}" } ], description: "Master Key for #{bucket_name}")
        kms_key_id = keyresp.key_metadata.key_id
        # Create a named alias for it to ease identification later on
        kms.create_alias(alias_name: "alias/#{key_alias}", target_key_id: kms_key_id)
        f="#{kms_key_id}.kms"
        File.open("#{f}", "wb") { |f| f.print kms_key_id }
        print "--> Generated new KMS key as #{kms_key_id}, placed in file #{f}. Probably want to check its policy settings in AWS.\n"
      else
        # If we get here we want to offer the user a list of available keys in the account
        resp = kms.list_keys()
        kms_key_array = resp.keys
        n = 0
        if kms_key_array.length > 1 then
          kms_key_array.each do |value|
            puts "      #{n}. ID: #{value.key_id}\n"
            n += 1
          end
          n -= 1
          print "----> Select index number [0 - #{n}] of KMS key you'd like to use: "
          choice = STDIN.gets.chomp.to_i
          kms_key_id = kms_key_array[choice].key_id
          puts "----> Selected [#{choice}]: #{kms_key_id}\n"
        else
          # Only 1 KMS key found, choose it!
          kms_key_id = kms_key_array[0].key_id
          puts "----> Single key found and selected: #{kms_key_id}"
        end
      end
    end

    # Read in our secret data from the file-system
    data = File.read(path_to_object)

    unless ENVENC then
      # Envelope encryption is false -- sadies :(
      print "--> Using KMS master key encryption\n"

      # Using KMS master key to encrypt object, can only handle max 4K worth of data
      objsize = File.size(path_to_object)
      if objsize > 4000 then
        puts "ERROR --> KMS master key encryption can only handle 4K worth of data (#{path_to_object} is #{objsize}K), try adding envelope encryption [-e]\n"
        exit
      end

      ### Additional layer of encryption available here if desired...
      ### client = Aws::S3::Encryption::Client.new(credentials: creds, kms_key_id: kms_key_id, kms_client: kms)

      # Bring up a s3 client
      client = Aws::S3::Client.new(credentials: creds)

      # What is our SSE mode?
      if sse_mode == "aws:kms" then
        # Using KMS for server-side encryption
        if enc_con == '' then
          # No encryption context to encode
          resp = kms.encrypt(key_id: kms_key_id, plaintext: "#{data}")
          obj = resp.ciphertext_blob
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, body:obj)
          puts "--> AWS-KMS master-key #{ctype} encryption w/ #{sse_mode} SSE of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          # Got encryption context lets encode it with the request
          resp = kms.encrypt(key_id: kms_key_id, plaintext: "#{data}", encryption_context: enc_con)
          obj = resp.ciphertext_blob
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, metadata: { "enc-context-keys" => "#{enc_keys}" }, body:obj)
          puts "--> AWS-KMS master-key #{ctype} encryption w/ #{sse_mode} SSE of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with encryption context\n"
        end
      else
        # default SSE mode of AES256
        if enc_con == '' then
          # No encryption context to encode, just request KMS encryption
          resp = kms.encrypt(key_id: kms_key_id, plaintext: "#{data}")
          obj = resp.ciphertext_blob
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", body:obj)
          puts "--> AWS-KMS master-key #{ctype} encryption w/ #{sse_mode} SSE of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          # Got encryption context lets encode it with the request and request KMS encryption
          resp = kms.encrypt(key_id: kms_key_id, plaintext: "#{data}", encryption_context: enc_con)
          obj = resp.ciphertext_blob
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", metadata: { "enc-context-keys" => "#{enc_keys}" }, body:obj)
          puts "--> AWS-KMS master-key #{ctype} encryption w/ #{sse_mode} SSE of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with encryption context\n"
        end
      end
    else
      # Envelope encryption is true!
      print "--> Using KMS envelope encryption\n"
      suffix = '.ekey'

      # Generate us a new data key from KMS locally
      genkey = ''
      if enc_con == '' then
        # No encryption context requested, just generate an object key
        genkey = kms.generate_data_key(key_id: kms_key_id, key_spec: "AES_256")
      else
        # Got some encryption context, lets encode it when we generate an object key
        genkey = kms.generate_data_key(key_id: kms_key_id, key_spec: "AES_256", encryption_context: enc_con)
      end

      # Store the encrypted copy of generated key as envelope for storage
      envelope = genkey.ciphertext_blob # no base64

      # Read our secret data into our temp object
      obj = "#{data}"

      # Startup a new s3 client and a new local encryption client
      s3 = Aws::S3::Client.new(credentials: creds)
      client = Aws::S3::Encryption::Client.new(encryption_key: genkey.plaintext, client: s3)

      ### An additional level of client-side encryption is available here, if so desired...
      ### client = Aws::S3::Encryption::Client.new(credentials: creds, kms_key_id: kms_key_id, kms_client: kms, envelope_location: :instruction_file, instruction_file_suffix: suffix)

      # What is our SSE mode?
      if sse_mode == "aws:kms" then
        # Requested SSE mode of aws:kms
        if enc_con == '' then
          # We are NOT using encryption context, client-side encrypt object using key generated above then put it up using 'aws:kms' SSE
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, metadata: { "kms-encryption-key-name" => "#{key_for_obj}#{suffix}" }, body:obj)
          # Put the already encrypted envelope up there using standard s3 client using 'aws:kms' SSE, adding KMS object name in metadata
          s3.put_object(bucket:bucket_name, key: "#{key_for_obj}#{suffix}", server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, metadata: { "kms-object-name" => "#{key_for_obj}" }, body:envelope)
          puts "--> AWS-KMS #{ctype} Envelope Encryption using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          # We have encryption context, client-side encrypt object using key generated above then put it using 'aws:kms' SSE adding encryption context key metadata
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, metadata: { "kms-encryption-key-name" => "#{key_for_obj}#{suffix}", "enc-context-keys" => "#{enc_keys}" }, body:obj)
          # Put the already encrypted envelope up there using standard s3 client using 'aws:kms' SSE, adding KMS object name in metadata
          s3.put_object(bucket:bucket_name, key: "#{key_for_obj}#{suffix}", server_side_encryption: "#{sse_mode}", ssekms_key_id: kms_key_id, metadata: { "kms-object-name" => "#{key_for_obj}" }, body:envelope)
          puts "--> AWS-KMS #{ctype} Envelope Encryption using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with encryption context\n"
        end
      else
        # SSE mode requested is AES256
        if enc_con == '' then
          # We are NOT using encryption context, client-side encrypt object using key generated above then put it up using 'AES256' SSE
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", metadata: { "kms-encryption-key-name" => "#{key_for_obj}#{suffix}" }, body:obj)
          # Put the already encrypted envelope up there using standard s3 client using 'AES256' SSE, adding KMS object name in metadata
          s3.put_object(bucket:bucket_name, key: "#{key_for_obj}#{suffix}", server_side_encryption: "#{sse_mode}", metadata: { "kms-object-name" => "#{key_for_obj}" }, body:envelope)
          puts "--> AWS-KMS #{ctype} Envelope Encryption using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name}\n"
        else
          # We are using encryption context, client-side encrypt object using key generated above then put it up using 'AES256' SSE adding encryption context key metadata
          client.put_object(bucket:bucket_name, key:key_for_obj, server_side_encryption: "#{sse_mode}", metadata: { "kms-encryption-key-name" => "#{key_for_obj}#{suffix}", "enc-context-keys" => "#{enc_keys}" }, body:obj)
          # Put the already encrypted envelope up there using standard s3 client using 'AES256' SSE, adding KMS object name in metadata
          s3.put_object(bucket:bucket_name, key: "#{key_for_obj}#{suffix}", server_side_encryption: "#{sse_mode}", metadata: { "kms-object-name" => "#{key_for_obj}" }, body:envelope)
          puts "--> AWS-KMS #{ctype} Envelope Encryption using #{key_for_obj}#{suffix} cipher of #{path_to_object} as key #{key_for_obj} in bucket #{bucket_name} with encryption context\n"
        end
      end
    end
  rescue Aws::S3::Errors::ServiceError => e
    puts "SSE-KMS (#{sse_mode}) Error encountered: #{e}"
  end
else
  # We get here if no actual known command was supplied
  print "ERROR --> '#{ARGV[0]}' is an unknown command, try one of 'cse', 'sse' or 'kms' modes\n"
  puts opt_parser
end
