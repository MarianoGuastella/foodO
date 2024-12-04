require 'sinatra'
require 'json'
require 'securerandom'
require 'bcrypt'

# Configure Sinatra to parse JSON
before do
  content_type :json
  request.body.rewind
  @request_payload = JSON.parse(request.body.read) rescue {}
end

USERS = {
  'admin' => BCrypt::Password.create('admin123')
}
TOKENS = {}
PRODUCTS = {}
PRODUCT_QUEUE = []

def authenticate_token
  token = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last
  halt 401, { error: 'Invalid or missing token' }.to_json unless TOKENS[token]
  TOKENS[token]
end

post '/auth' do
  username = @request_payload['username']
  password = @request_payload['password']

  halt 400, { error: 'Missing credentials' }.to_json unless username && password
  
  stored_password = USERS[username]
  halt 401, { error: 'Invalid credentials' }.to_json unless stored_password
  
  unless BCrypt::Password.new(stored_password) == password
    halt 401, { error: 'Invalid credentials' }.to_json
  end

  token = SecureRandom.hex(32)
  TOKENS[token] = username
  
  { token: token }.to_json
end

post '/products' do
  authenticate_token
  
  name = @request_payload['name']
  id = @request_payload['id']
  
  halt 400, { error: 'Missing product data' }.to_json unless name && id
  
  if PRODUCTS[id] || PRODUCTS.values.any? { |p| p[:name] == name }
    halt 409, { error: 'Product with this ID or name already exists' }.to_json
  end
  
  PRODUCT_QUEUE << { id: id, name: name }
  
  Thread.new do
    sleep 2
    PRODUCTS[id] = { id: id, name: name }
    { message: 'Product created' }.to_json
  end
  
  { message: 'Product creation in progress' }.to_json
end

get '/products' do
  authenticate_token
  PRODUCTS.values.to_json
end
