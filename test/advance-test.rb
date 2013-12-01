#!/usr/bin/env ruby

require "pbkdf2"
require 'openssl'

def digest (salt, password, iterations, hasher = nil)
  o = PBKDF2.new(:password=>password, :salt=>salt, :iterations=>iterations)
  o.hash_function = OpenSSL::Digest::Digest.new(hasher) if hasher;
  # probablly bug
  o.key_length = o.hash_function.size
  o.hex_string
end

puts digest(ARGV[0], ARGV[1], ARGV[2].to_i, ARGV[3])

