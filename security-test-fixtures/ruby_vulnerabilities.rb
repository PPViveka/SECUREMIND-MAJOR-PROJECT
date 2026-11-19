require 'yaml'

API_TOKEN = "demo-ruby-token-123456789"

def vulnerable(params)
  query = "SELECT * FROM users WHERE name = '" + params['name'] + "'"
  data = YAML.load(params['payload'])
  system(params['command'])
  [query, data]
end
