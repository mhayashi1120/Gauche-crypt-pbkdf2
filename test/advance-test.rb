#!/usr/bin/env ruby

require "pbkdf2"
require 'openssl'

def digest (password, salt, iterations, hasher = nil, len = nil)
  o = PBKDF2.new(:password=>password, :salt=>salt, :iterations=>iterations)
  o.hash_function = OpenSSL::Digest::Digest.new(hasher) if hasher;
  # probablly bug
  o.key_length = o.hash_function.size
  # overwrite if is specified
  o.key_length = len if len;
  o.hex_string
end

puts digest(ARGV[0], ARGV[1], ARGV[2].to_i, ARGV[3], ARGV[4] ? ARGV[4].to_i : nil)

