require 'sinatra'
require 'json'
require 'securerandom'
require 'bcrypt'
require 'logger'
require 'sanitize'
require 'dotenv/load'

logger = Logger.new('app.log')
logger.level = Logger::INFO

before do
  content_type :json
  request.body.rewind
  begin
    @request_payload = JSON.parse(request.body.read)
  rescue JSON::ParserError => e
    logger.error "Invalid JSON payload: #{e.message}"
    halt 400, { error: 'Invalid JSON payload' }.to_json
  end
end

USERS = {
  ENV.fetch('ADMIN_USERNAME') => BCrypt::Password.create(ENV.fetch('ADMIN_PASSWORD'))
}
TOKENS = {}
PRODUCTS = {}
PRODUCT_QUEUE = []

def authenticate_token
  token = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last
  halt 401, { error: 'Invalid or missing token' }.to_json unless TOKENS[token]
  TOKENS[token]
rescue => e
  logger.error "Authentication error: #{e.message}"
  halt 500, { error: 'Internal server error' }.to_json
end

def validate_product(name, id)
  return 'Product name is required' if name.nil? || name.strip.empty?
  return 'Product ID is required' if id.nil? || id.strip.empty?
  return 'Invalid product name format' unless name.match?(/^[a-zA-Z0-9\s-]{2,50}$/)
  return 'Invalid product ID format' unless id.match?(/^[a-zA-Z0-9-]{2,20}$/)
  nil
end

post '/auth' do
  username = Sanitize.fragment(@request_payload['username'].to_s)
  password = @request_payload['password'].to_s

  halt 400, { error: 'Missing credentials' }.to_json unless username && password
  
  stored_password = USERS[username]
  halt 401, { error: 'Invalid credentials' }.to_json unless stored_password
  
  unless BCrypt::Password.new(stored_password) == password
    logger.warn "Failed login attempt for user: #{username}"
    halt 401, { error: 'Invalid credentials' }.to_json
  end

  token = SecureRandom.hex(32)
  TOKENS[token] = username
  
  logger.info "Successful login for user: #{username}"
  { token: token }.to_json
rescue => e
  logger.error "Authentication error: #{e.message}"
  halt 500, { error: 'Internal server error' }.to_json
end

post '/products' do
  user = authenticate_token
  
  name = Sanitize.fragment(@request_payload['name'].to_s)
  id = Sanitize.fragment(@request_payload['id'].to_s)
  
  if error = validate_product(name, id)
    halt 400, { error: error }.to_json
  end
  
  if PRODUCTS[id] || PRODUCTS.values.any? { |p| p[:name] == name }
    logger.warn "Duplicate product attempt - ID: #{id}, Name: #{name}"
    halt 409, { error: 'Product with this ID or name already exists' }.to_json
  end
  
  PRODUCT_QUEUE << { id: id, name: name }
  
  Thread.new do
    sleep 2
    PRODUCTS[id] = { id: id, name: name }
    { message: 'Product created' }.to_json
  end
  
  logger.info "Product creation queued - ID: #{id}, Name: #{name}, User: #{user}"
  { message: 'Product creation in progress' }.to_json
rescue => e
  logger.error "Product creation error: #{e.message}"
  halt 500, { error: 'Internal server error' }.to_json
end

get '/products' do
  user = authenticate_token
  logger.info "Products list requested by user: #{user}"
  PRODUCTS.values.to_json
rescue => e
  logger.error "Product listing error: #{e.message}"
  halt 500, { error: 'Internal server error' }.to_json
end
