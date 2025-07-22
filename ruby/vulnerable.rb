require 'sinatra'
require 'pg'
require 'open-uri'
require 'yaml'
require 'erb'

# 1. SQL Injection
def vulnerable_sql(conn, username)
  query = "SELECT * FROM users WHERE username = '#{username}'"
  conn.exec(query)  # SQL Injection
end

# 2. XSS
get '/xss' do
  user_input = params[:input]
  "<div>#{user_input}</div>"  # XSS
end

# 3. Command Injection
def vulnerable_command_injection(user_input)
  `echo #{user_input}`  # Command Injection
end

# 4. Path Traversal
def vulnerable_path_traversal(filename)
  File.read("/home/user/#{filename}")  # Path Traversal
end

# 5. Insecure Deserialization
def vulnerable_deserialization(yaml_data)
  YAML.load(yaml_data)  # Insecure Deserialization
end

# 6. Server-Side Request Forgery (SSRF)
def vulnerable_ssrf(url)
  open(url).read  # SSRF
end

# 7. Insecure Direct Object Reference (IDOR)
def vulnerable_idor(user_id)
  "/userdata/#{user_id}.txt"  # IDOR
end

# 8. Security Misconfiguration
configure do
  # Disabling security features
  set :protection, false  # Disables CSRF protection
  set :show_exceptions, :after_handler  # Leaks stack traces
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
