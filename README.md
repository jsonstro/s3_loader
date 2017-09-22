## *** README for s3_loader ***

The intention of this project is to assist with managing secrets using OPSWorks Stacks. It offers many ways to encrypt a secret & store it in s3. Assumes you are using roles or at minimum are a named user in your AWS account. 

The decryption script will enable you to verify your work. It also will decrpyt the secret to standard out (if requested), so it may be wrapped for automation in another script via the shell.

 - Help is available from the script by providing the '-h' or "--help" options.
 - General config options can be specified either from the cmd line flags or in a config file in current directory called 's3_loader.yaml'.
   * Override individual settings per AWS profile in a YAML file called '<PROFILE>.yaml', where <PROFILE> is the EXACT name/case of profile name in .aws/config
   * For example if you have "[profile AWS-Test]" in your .aws/config, your profile YAML file should be called 'AWS-Test.yaml'
 - Script will honor your normal AWS environment configuration in ~/.aws/credentials and ~/.aws/config respectively. 
 - KMS mode will allow for encryption context, a comma separated list of arbitrary 'key=value' pairs that should be able to be programatically generated, e.g. layer=AppLayer or dir=/some/path/to/file or user=autosys,table=autora1. List of keys will be stored in metadata of object.
 - With KMS envelope encryption the datakey will be stored encrypted alongside the object in s3 with an extension of '.ekey'.
 - The encryption script verifies that the bucket is not publically readable before pushing your secret and will fail if ACLs are too wide.
 - The script offers cipher/key generation for both AES and RSA client-side encryption as well as KMS key selection/creation when '-m' flag or 'kms' modes are used.

In the './examples' dir you can find demo chef code to decode each method and type of encryption below, as well as example AWS s3 bucket policies to limit a bucket's uploads to be encrypted.

I. List of available uses is below:
1. __Mode CSE__

   For both types the name of the key will be stored in metadata of object.

      A. Client-side asymmetric encryption with a PEM-encoded RSA cert:  
         (Can use a password protected encrypted key)

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -c <name>.pem -r

      B. Client-side symmetric encryption with an AES256 cipher:

        % ./encrypt_upload_to_s3.rb cse <OBJECT> -c <name>.aes


2. __Mode SSE__

    C. Server-side symmetric encryption with a s3-managed AES256 cipher:

        % ./encrypt_upload_to_s3.rb sse <OBJECT> 

    D. Server-side symmetric encryption with a client-managed AES256 cipher:  
       (Name of the key will be stored in metadata of object.)

        % ./encrypt_upload_to_s3.rb sse <OBJECT> -c <name>.aes

    E. Server-side symmetric encryption with a KMS-managed AES256 cipher:

        % ./encrypt_upload_to_s3.rb sse <OBJECT> -m


3. __Mode KMS__

    F. Client-side symmetric KMS master key encryption with either s3- or KMS-managed AES256 server-side symmetric encryption: 

       % ./encrypt_upload_to_s3.rb kms <OBJECT>

     or

       % ./encrypt_upload_to_s3.rb kms <OBJECT> -m

    G. Client-side symmetric KMS master key encryption using encryption context with either s3- or KMS-managed AES256 server-side symmetric encryption:
 
       % ./encrypt_upload_to_s3.rb kms <OBJECT> <CONTEXT>

     or

       % ./encrypt_upload_to_s3.rb kms <OBJECT> <CONTEXT> -m

    H. Client-side symmetric envelope encryption with either s3- or KMS-managed server-side AES256 symmetric encryption:

       % ./encrypt_upload_to_s3.rb kms <OBJECT> -e

     or

       % ./encrypt_upload_to_s3.rb kms <OBJECT> -e -m

     I. Client-side symmetric envelope encryption with either s3- or KMS-managed server-side AES256 symmetric encryption with encryption context:

       % ./encrypt_upload_to_s3.rb kms <OBJECT> <CONTEXT> -e

     or

       % ./encrypt_upload_to_s3.rb kms <OBJECT> <CONTEXT> -e -m


4. __Mode Generate__  
We can also generate a new RSA cert, AES cipher, or KMS master key as well:

     J. Generate a new RSA cert:

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -g RSA
     or

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -g RSA,<name>.pem

     K. Generate a new AES cipher:

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -g AES
     or

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -g AES,<name>.aes

     L. Generate a new KMS master key or select from existing:

       % ./encrypt_upload_to_s3.rb cse <OBJECT> -g KMS

