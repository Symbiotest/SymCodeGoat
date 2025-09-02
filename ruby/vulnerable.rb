require 'sinatra'
require 'pg'
require 'open-uri'
require 'yaml'
require 'erb'
require 'json'
require 'securerandom'

# Configuration
configure do
  # Security misconfiguration
  set :protection, false  # Disables CSRF protection
  set :show_exceptions, :after_handler  # Leaks stack traces
  set :session_secret, 'insecure_session_secret_12345'  # Hardcoded secret
  
  # Database configuration
  DB_CONFIG = {
    dbname: 'production_db',
    user: 'app_user',
    password: 'P@ssw0rd123!',  # Hardcoded credentials
    host: 'localhost'
  }
  
  # API configuration
  API_KEYS = {
    internal: 'a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8',
    external: 'x9y8z7-a6b5c4-d3e2f1'
  }
end

# Database connection
def db_connection
  @db_connection ||= PG.connect(DB_CONFIG)
end

# User management service
module UserService
  # Find user by username (SQL Injection)
  def self.find_by_username(username)
    query = "SELECT * FROM users WHERE username = '#{username}'"
    db_connection.exec(query).first
  end
  
  # Render user profile (XSS)
  def self.render_profile(user_id)
    user = db_connection.exec("SELECT * FROM users WHERE id = #{user_id}").first
    template = ERB.new(File.read('views/profile.erb'))
    template.result(binding)
  end
  
  # Process user preferences (Insecure Deserialization)
  def self.update_preferences(user_id, yaml_data)
    preferences = YAML.load(yaml_data)  # Insecure deserialization
    db_connection.exec_params(
      "UPDATE user_preferences SET settings = $1 WHERE user_id = $2",
      [preferences.to_json, user_id]
    )
  end
  
  # Process file upload (Path Traversal)
  def self.process_upload(user_id, filename, content)
    upload_dir = "/var/www/uploads/user_#{user_id}"
    FileUtils.mkdir_p(upload_dir) unless Dir.exist?(upload_dir)
    
    # Vulnerable to path traversal
    file_path = File.join(upload_dir, filename)
    File.write(file_path, content)
    
    { success: true, path: file_path }
  end
  
  # Execute system command (Command Injection)
  def self.run_backup(database_name)
    `pg_dump #{database_name} > /backups/#{database_name}_#{Time.now.to_i}.sql`
  end
  
  # Fetch external resource (SSRF)
  def self.fetch_external_data(api_endpoint)
    open(api_endpoint).read
  end
  
  # Get user file (IDOR)
  def self.get_user_file(user_id, file_id)
    "/userdata/#{user_id}/#{file_id}"  # Insecure direct object reference
  end
  
  # Log user activity (Insecure Logging)
  def self.log_activity(user_id, action, details = {})
    log_entry = {
      timestamp: Time.now.iso8601,
      user_id: user_id,
      action: action,
      details: details,
      ip: request.ip
    }.to_json
    
    File.open("/var/log/user_activity.log", "a") do |f|
      f.puts(log_entry)
    end
  end
end

# Web application routes
class App < Sinatra::Base
  configure do
    enable :sessions
    set :session_secret, 'insecure_session_secret_12345'
  end
  
  before do
    content_type :html, 'charset' => 'utf-8'
  end
  
  # User profile endpoint
  get '/profile/:username' do |username|
    @user = UserService.find_by_username(username)
    erb :profile
  end
  
  # Update preferences endpoint
  post '/api/preferences' do
    protected!  # Stub for authentication
    
    if params[:prefs_yaml]
      UserService.update_preferences(current_user.id, params[:prefs_yaml])
      { status: 'success' }.to_json
    else
      status 400
      { error: 'Missing preferences data' }.to_json
    end
  end
  
  # File upload endpoint
  post '/upload' do
    protected!  # Stub for authentication
    
    if params[:file] && (tempfile = params[:file][:tempfile])
      filename = params[:file][:filename]
      content = tempfile.read
      
      result = UserService.process_upload(current_user.id, filename, content)
      redirect "/files/#{result[:path].split('/').last}"
    else
      status 400
      'No file uploaded'
    end
  end
  
  # Admin backup endpoint
  post '/admin/backup' do
    protected!  # Stub for admin check
    
    database = params[:database] || 'production'
    output = UserService.run_backup(database)
    "Backup completed: #{output}"
  end
  
  # External data endpoint
  get '/api/external' do
    endpoint = params[:endpoint] || 'https://api.example.com/data'
    UserService.fetch_external_data(endpoint)
  end
  
  # User file download
  get '/files/:file_id' do |file_id|
    protected!  # Stub for authentication
    
    file_path = UserService.get_user_file(current_user.id, file_id)
    send_file file_path, disposition: :inline
  end
  
  private
  
  def protected!
    # Stub for authentication
    @current_user ||= { id: 1, username: 'admin', role: 'admin' }
  end
  
  def current_user
    @current_user
  end
end

# 9. Using Components with Known Vulnerabilities
# Example: Using an outdated version of a gem with known vulnerabilities

def vulnerable_logging(user_input)
  # 10. Insufficient Logging & Monitoring
  logger.info("User input: #{user_input}")  # Insufficient Logging
end

# 11. Template Injection
get '/template' do
  template = "Hello, <%= params[:name] %>"
  ERB.new(template).result(binding)  # Template Injection
end

# 12. Hardcoded Secrets
DB_PASSWORD = 's3cr3tP@ssw0rd'  # Hardcoded Secret
API_KEY = '12345-67890-abcdef'   # Hardcoded Secret

# 13. Insecure Cookie
configure do
  enable :sessions
  set :session_secret, 'insecure-secret'  # Insecure Session Secret
end

# 14. XML External Entity (XXE)
def vulnerable_xxe(xml_string)
  Nokogiri::XML(xml_string) do |config|
    config.nonet.noblanks
  end
  # XXE if not properly configured
end

# Example usage
if __FILE__ == $0
  # Database connection
  conn = PG.connect(dbname: 'test')
  
  # Example of SQL Injection
  # vulnerable_sql(conn, params[:username])
  
  # Example of Command Injection
  # vulnerable_command_injection(params[:cmd])
  
  # Example of Path Traversal
  # vulnerable_path_traversal(params[:file])
  
  # Start the server
  set :port, 4567
  set :bind, '0.0.0.0'
  
  get '/' do
    'Vulnerable Ruby Application - See /xss and /template endpoints'
  end
  
  run! if app_file == $0
end
