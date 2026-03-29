#!/usr/bin/env ruby
require 'bundler/inline'
gemfile do
  source 'https://rubygems.org'
  gem 'rexml'
  gem 'aws-sdk-core'
end

require 'aws-sdk-sts'
require 'net/http'
require 'json'
require 'uri'
require 'base64'

base_url = ARGV[0] || 'https://sts-cat.lo.nkmiusercontent.com:1443'
audience = ARGV[1] || URI.parse(base_url).host

sts = Aws::STS::Client.new(region: ENV.fetch('AWS_REGION', 'ap-northeast-1'))

puts "=== Getting web identity token (audience: #{audience}) ==="
resp = sts.get_web_identity_token(
  audience: [audience],
  signing_algorithm: 'RS256',
)
token = resp.web_identity_token

parts = token.split('.')
payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + '=' * (4 - parts[1].length % 4)))
puts "  iss: #{payload['iss']}"
puts "  sub: #{payload['sub']}"
puts "  aud: #{payload['aud']}"
puts "  exp: #{Time.at(payload['exp']).utc}"
puts

test_cases = [
  { name: 'Repo-level allowed',  scope: 'nkmi-test/foo', identity: 'e2e-test',            expect: 200, verify_repos: ['nkmi-test/foo'], verify_perms: { 'contents' => 'read' } },
  { name: 'Repo-level denied',   scope: 'nkmi-test/foo', identity: 'e2e-test-denied',     expect: 403 },
  { name: 'Org-level allowed',   scope: 'nkmi-test',     identity: 'e2e-test-org',         expect: 200, verify_repos: ['nkmi-test/bar'], verify_perms: { 'contents' => 'read' } },
  { name: 'Org-level denied',    scope: 'nkmi-test',     identity: 'e2e-test-org-denied',  expect: 403 },
]

def verify_github_token(gh_token, expected_repos:, expected_perms:)
  # Check token metadata via GitHub API
  uri = URI.parse('https://api.github.com/installation/token')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  req = Net::HTTP::Get.new(uri.path)
  req['Authorization'] = "Bearer #{gh_token}"
  req['Accept'] = 'application/vnd.github+json'
  resp = http.request(req)

  # Also try listing accessible repos
  uri2 = URI.parse('https://api.github.com/installation/repositories')
  req2 = Net::HTTP::Get.new(uri2.path)
  req2['Authorization'] = "Bearer #{gh_token}"
  req2['Accept'] = 'application/vnd.github+json'
  resp2 = http.request(req2)

  errors = []

  if resp2.code.to_i == 200
    repos_data = JSON.parse(resp2.body)
    repo_names = repos_data['repositories'].map { |r| r['full_name'] }
    expected_repos.each do |er|
      unless repo_names.include?(er)
        errors << "expected repo #{er} not in accessible repos: #{repo_names}"
      end
    end
    # Verify token is scoped only to expected repos
    unexpected = repo_names - expected_repos
    unless unexpected.empty?
      errors << "unexpected repos accessible: #{unexpected}"
    end
  else
    errors << "failed to list repos (#{resp2.code}): #{resp2.body}"
  end

  # Try reading contents to verify permission works
  expected_repos.each do |repo|
    uri3 = URI.parse("https://api.github.com/repos/#{repo}/contents/")
    req3 = Net::HTTP::Get.new(uri3.path)
    req3['Authorization'] = "Bearer #{gh_token}"
    req3['Accept'] = 'application/vnd.github+json'
    resp3 = http.request(req3)
    unless resp3.code.to_i == 200
      errors << "contents read on #{repo} failed (#{resp3.code})"
    end
  end

  errors
end

endpoint = URI.parse("#{base_url}/token")
results = []

test_cases.each_with_index do |tc, i|
  print "#{i + 1}. #{tc[:name]} (scope=#{tc[:scope]} identity=#{tc[:identity]}) ... "

  http = Net::HTTP.new(endpoint.host, endpoint.port)
  if endpoint.scheme == 'https'
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end

  req = Net::HTTP::Post.new(endpoint.path)
  req['Authorization'] = "Bearer #{token}"
  req['Content-Type'] = 'application/json'
  req.body = JSON.generate({ scope: tc[:scope], identity: tc[:identity] })

  resp = http.request(req)
  status = resp.code.to_i
  body = resp.body

  pass = status == tc[:expect]
  results << pass

  if pass
    puts "\e[32mPASS\e[0m (#{status})"
  else
    puts "\e[31mFAIL\e[0m (expected #{tc[:expect]}, got #{status})"
  end
  puts "     #{body}"

  # Verify vended GitHub token if exchange succeeded
  if status == 200 && tc[:verify_repos]
    gh_token = JSON.parse(body)['token']
    print "     Verifying GitHub token ... "
    errors = verify_github_token(gh_token, expected_repos: tc[:verify_repos], expected_perms: tc[:verify_perms])
    if errors.empty?
      puts "\e[32mOK\e[0m"
    else
      puts "\e[31mFAILED\e[0m"
      errors.each { |e| puts "       - #{e}" }
      results[-1] = false
    end
  end
  puts
end

puts "=== Summary ==="
passed = results.count(true)
total = results.length
if passed == total
  puts "\e[32mAll #{total} tests passed\e[0m"
else
  puts "\e[31m#{passed}/#{total} tests passed\e[0m"
  exit 1
end
