#!/usr/bin/env ruby
require 'digest'
require 'socket'

ID_STRING  = "SSH-2.0-simple"

# literally wikipedia example numbers
HOST_KEY_N = 2**1024 # 3233
HOST_KEY_E = 17


class String
  def bytes
    each_char.map(&:ord)
  end
end

class Array
  # all of those functions are only meant to be used with byte arrays
  # they strip the type from the beginning and return it
  #
  # definitions of all those types (and those below too) are in RFC 4251 / 5.

  def uint32
    shift(4).pack('C*').unpack('N').first
  end

  def mpint
    len = uint32
    val = 0
    shift(len).each do |d|
      val = val * 256 + d
    end
    # todo negatives
    val
  end

  def name_list
    len = uint32
    shift(len).map(&:chr).join.split(',')
  end
end

class TCPSocket
  def read_byte
    read(1).ord
  end

  def read_uint32
    read(4).unpack('N').first
  end

  # RFC 4253 / 6.
  def read_packet
    packet_length = read_uint32
    padding_length = read_byte
    payload = read(packet_length - padding_length - 1).bytes
    padding = read(padding_length).bytes

    # todo mac
    
    payload
  end

  def send_packet payload
    # min of (8, cipher block size)
    multiple = 8

    # 4 + 1 + payload.length + padding_length = 0 (mod multiple)
    # padding_length = - 5 - payload.length (mod multiple)
    padding_length = (- 5 - payload.length) % multiple
    padding_length += 16 # doesn't work without this, no idea why - todo
    packet_length  = payload.length + padding_length + 1

    packet  = ssh_uint32 packet_length
    packet += ssh_byte padding_length
    packet += payload
    packet += [0] * padding_length # Random.bytes(padding_length).bytes
    # todo mac
    padding_length
    packet

    send packet.map(&:chr).join, 0
  end
end

def ssh_byte i
  [i.ord]
end

def ssh_uint32 i
  [i].pack('N').bytes
end

def ssh_string s
  a = s.bytes
  ssh_uint32(a.length) + a
end

# awful
def ssh_pmint i
  # convert negative numbers
  negative = false
  if i < 0
    negative = true
    byte_len = Math.log(-i, 256).ceil
    i = 256**byte_len + i
  end

  # convert i to bytes, msb first
  bytes = []
  while i > 0
    bytes.unshift(i & 0xff)
    i = i >> 8
  end

  if bytes != []
    # extract the most significant bit
    # for positive numbers it must be 0, negative 1
    msb = bytes[0] & 0x80 != 0

    if msb ^ negative # if it isn't, we must insert a padding byte
      padding = if negative then 255 else 0 end
      bytes.unshift padding
    end
  end

  ssh_uint32(bytes.length) + bytes
end


# RFC 4253 / 7.
def algo_negotiation cl
  # let's prepare our packet first
  our_cookie = Random.bytes(16).bytes

  payload  = [20] # SSH_MSG_KEXINIT
  payload += our_cookie
  payload += ssh_string "diffie-hellman-group14-sha256" # key exchange
  payload += ssh_string "ssh-rsa"                       # server host key
  payload += ssh_string "aes256-ctr"                    # c2s encryption
  payload += ssh_string "aes256-ctr"                    # s2c ^
  payload += ssh_string "hmac-sha2-256"                 # c2s mac
  payload += ssh_string "hmac-sha2-256"                 # s2c ^
  payload += ssh_string "none"                          # c2s compression
  payload += ssh_string "none"                          # s2c ^
  payload += ssh_string ""                              # c2s languages
  payload += ssh_string ""                              # s2c ^
  payload += [0]          # no kex packet follows
  payload += ssh_uint32 0 # reserved
  
  cl.send_packet payload

  # parsing the client's packet
  packet = cl.read_packet
  packet_copy = packet.dup
  raise "invalid packet" unless
    packet.shift == 20 # SSH_MSG_KEXINIT

  client_cookie         = packet.shift 16
  kex_algorithms        = packet.name_list
  raise "unsupported" unless
    kex_algorithms.include? "diffie-hellman-group14-sha256"

  server_host_key_algos = packet.name_list 
  raise "unsupported" unless
    server_host_key_algos.include? "ssh-rsa"

  encryption_algos_c2s  = packet.name_list 
  encryption_algos_s2c  = packet.name_list 
  raise "unsupported" unless
    encryption_algos_c2s.include? "aes256-ctr" and
    encryption_algos_s2c.include? "aes256-ctr"

  mac_algos_c2s         = packet.name_list 
  mac_algos_s2c         = packet.name_list 
  raise "unsupported" unless
    mac_algos_c2s.include? "hmac-sha2-256" and
    mac_algos_s2c.include? "hmac-sha2-256"

  compression_algos_c2s = packet.name_list 
  compression_algos_s2c = packet.name_list 
  raise "unsupported" unless
    compression_algos_c2s.include? "none" and
    compression_algos_s2c.include? "none"

  # we don't care about those
  _languages_c2s        = packet.name_list
  _languages_s2c        = packet.name_list

  first_kex_packet_follows = packet.shift != 0
  raise "unsupported" if first_kex_packet_follows # TODO

  _reserved = packet.uint32

  payload + packet_copy # we return the combined payloads for use in the key exchange
end

# RFC 3526 / 3.
# prime used for the DH key exchange
DH14P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

# RFC 4253 / 8.
# using diffie-hellman-group14-sha256
def key_exchange cl, client_id, combined_payloads
  ### 1. the client sends us E
  packet = cl.read_packet
  raise "invalid packet" unless
    packet.shift == 30 # SSH_MSG_KEXDH_INIT
  e = packet.mpint # todo verify that e is in [1, p-1]


  ### 2. we send the client our host key, and do some crypto stuff
  payload = [31] # SSH_MSH_KEXDH_REPLY
  
  # encoded according to RFC 4253 / 6.6.
  encoded_host_key  = ssh_string "ssh-rsa"
  encoded_host_key += ssh_pmint HOST_KEY_E
  encoded_host_key += ssh_pmint HOST_KEY_N
  encoded_host_key  = encoded_host_key.map(&:chr).join # convert to string
  payload += ssh_string encoded_host_key

  # calculating the DH stuff
  y = rand(1..DH14P)
  f = 2.pow(y, DH14P)
  k = e.pow(y, DH14P)
  # and sending it
  payload += ssh_pmint f

  # and sending the signature
  sha = Digest::SHA256.new
  sha << client_id                         # V_C
  sha << ID_STRING                         # V_S
  sha << combined_payloads.map(&:chr).join # I_C || I_S
  sha << encoded_host_key                  # K_S
  sha << ssh_pmint(e).map(&:chr).join      # e
  sha << ssh_pmint(f).map(&:chr).join      # f
  sha << ssh_pmint(k).map(&:chr).join      # K

  hash = sha.hexdigest

  # RFC 4253 / 6.6.
  signature  = ssh_string "ssh-rsa"
  signature += ssh_string "penis"
  signature  = signature.map(&:chr).join
  payload   += ssh_string signature
 
#  The value for 'rsa_signature_blob' is encoded as a string containing
#  s (which is an integer, without lengths or padding, unsigned, and in
#  network byte order).
  cl.send_packet payload
end

def handle_client cl
  begin
    # version exchange
    # todo not spec compliant
    client_id = cl.gets.delete_suffix("\r\n")
    puts client_id + " connected"
    cl.write ID_STRING + "\r\n"

    combined_payloads = algo_negotiation cl
    # since this is a toy implementation i don't have to carry all the
    # negotiated algos arounds - only one of each is supported
    key_exchange cl, client_id, combined_payloads
  ensure
    cl.close
  end
end



STDOUT.sync = true
server = TCPServer.new 22
loop do
  Thread.start(server.accept) {|c| handle_client c}
end
