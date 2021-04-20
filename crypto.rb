require 'digest'

# RFC 3447 / 8.2.1.
# i assume SHA1 as the hash function used
def rsa_sign arr
  # RFC 3447 / 9.2.
  hash = Digest::SHA1.digest arr.map(&:chr).join

  # RFC 3447 / page 43
  digest_info = [0x30, 0x21, 0x30, 0x09, 0x06,
                 0x05, 0x2b, 0x0e, 0x03, 0x02,
                 0x1a, 0x05, 0x00, 0x04, 0x14].map(&:chr).join

  # i don't do the padding, openssl does that for me
  # i'll reimplement RSA later on
  signature = HOST_KEY.private_encrypt(digest_info + hash)
end

# byte array -> byte array
def SHA256 arr
  Digest::SHA256.digest(arr.map(&:chr).join).bytes
end

# returns an infinite byte stream to xor against
# arguments are arrays
def AES256_ctr key, iv
    cipher = OpenSSL::Cipher::AES.new(256, :ECB)
    cipher.encrypt
    cipher.padding = 0
    cipher.key = key[..31].map(&:chr).join

    counter = iv[..15]
    f = Fiber.new do
      loop do
        enc = cipher.update(counter.map(&:chr).join)
        enc.bytes.each {|b| Fiber.yield b}
        counter.increment
      end
    end

    Enumerator.produce {f.resume}
end

# byte array -> byte array
# RFC 2104
def HMAC_SHA2_256 key, msg
  # skipping the key hashing step, as we can assume that it's small enough
  blockSize = 512 / 8
  key = key.ljust blockSize, 0
  o_padded = key.xor ([0x5c] * blockSize).each
  i_padded = key.xor ([0x36] * blockSize).each

  o = SHA256(o_padded + SHA256(i_padded + msg))
end


# dumb wrapper functions
class TCPSocket
  attr_accessor :c2s_cipher
  attr_accessor :s2c_cipher

  def proxy_read len
    arr = read(len).bytes
    if @c2s_cipher
      arr = arr.xor @c2s_cipher
    end
    arr.map(&:chr).join
  end

  def proxy_send arr
    if @s2c_cipher
      arr = arr.xor @s2c_cipher
    end
    send arr.map(&:chr).join, 0
  end
end
