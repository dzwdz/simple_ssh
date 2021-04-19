# RFC 3447 / 8.2.1.
# i assume SHA1 as the hash function used
def rsa_sign str
  # RFC 3447 / 9.2.
  hash = Digest::SHA1.digest str

  # RFC 3447 / page 43
  digest_info = [0x30, 0x21, 0x30, 0x09, 0x06,
                 0x05, 0x2b, 0x0e, 0x03, 0x02,
                 0x1a, 0x05, 0x00, 0x04, 0x14].map(&:chr).join

  # i don't do the padding, openssl does that for me
  # i'll reimplement RSA later on
  signature = HOST_KEY.private_encrypt(digest_info + hash)
end
