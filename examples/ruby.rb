# VDB API Testing - AWS SigV4 Authentication Example (Ruby)
# Requires: gem install aws-sigv4

require 'aws-sigv4'
require 'net/http'
require 'uri'
require 'json'
require 'openssl'

# Step 1: Configuration - Set your Organization credentials
VVD_ORG = "f7c11fc1-d422-4242-a05e-ea3e747b07bc" # Organization UUID (used as access key)
VVD_SECRET = "ldCTA9jeOLtHdkByhLl8DyIIo5bd2Meb6IA4rATn0KCanfzU2s97CTBQ7bxtYTIs" # Organization Secret (64 chars)
VVD_ACCESS_KEY = VVD_ORG # Access key is the Organization UUID

# Step 2: Create AWS Sigv4 Signer
signer = Aws::Sigv4::Signer.new(
  service: 'vdb',
  region: 'us-east-1',
  access_key_id: VVD_ACCESS_KEY,
  secret_access_key: VVD_SECRET,
  uri_escape_path: true,
  apply_checksum_header: false
)

# Step 3: Get JWT token from /v1/auth/token
def get_jwt_token(signer, host)
  # Prepare the request
  url = URI("https://#{host}/auth/token")
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  
  # Create the request
  request = Net::HTTP::Get.new(url.request_uri)
  
  # Sign the request using AWS SigV4
  signature = signer.sign_request(
    http_method: 'GET',
    url: url.to_s,
    headers: {},
    body: ''
  )
  
  # Apply signed headers to request
  signature.headers.each do |key, value|
    request[key] = value
  end
  
  # Make the request
  response = http.request(request)
  
  # Parse the response
  if response.code.to_i == 200
    data = JSON.parse(response.body)
    puts "JWT token obtained (expires in 15 minutes): #{data['token'][0..50]}..."
    puts "Token details:"
    puts "  iss: #{data['iss']}"
    puts "  sub: #{data['sub']}"
    puts "  exp: #{Time.at(data['exp']).utc}"
    return data['token']
  else
    raise "Failed to obtain JWT token: #{response.code} #{response.body}"
  end
end

# Step 4: Make authenticated API request
def make_api_request(jwt_token, host, path)
  url = URI("https://#{host}#{path}")
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  
  request = Net::HTTP::Get.new(url.request_uri)
  request['Authorization'] = "Bearer #{jwt_token}"
  request['Content-Type'] = 'application/json'
  
  response = http.request(request)
  data = JSON.parse(response.body)
  
  puts "API Response:"
  puts JSON.pretty_generate(data)
  
  data
end

# Execute the requests
begin
  host = "api.vdb.vulnetix.com"
  
  # Get JWT token
  jwt_token = get_jwt_token(signer, host)
  
  # Make GET request to /ecosystems
  result = make_api_request(jwt_token, host, "/ecosystems")
rescue StandardError => e
  puts "Error: #{e.message}"
  puts e.backtrace
end
