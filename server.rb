#!/usr/bin/env ruby
require 'socket'
require 'openssl'
require 'base64' # only used internally

# i've split off the stuff that isn't specific to SSH into seperate files
require_relative 'utility'
require_relative 'crypto'


ID_STRING  = "SSH-2.0-simple"
HOST_KEY = OpenSSL::PKey::RSA.new File.read 'host_key'




# first off - we need functions for handling the SSH types
# RFC 4251 / 5.

class Array
  # all of those functions are only meant to be used with byte arrays
  # they strip the value from the beginning and return it

  def uint32
    shift(4).pack('C*').unpack('N').first
  end

  def mpint
    len = uint32
    val = shift(len).to_i
    # todo negatives
    val
  end

  def string
    len = uint32
    shift(len).map(&:chr).join
  end

  def name_list
    string.split(',')
  end
end

class TCPSocket
  # proxy_read is provided by crypto.rb
  # it just decrypts the bytes that it reads
  attr_accessor :c2s_mac
  attr_accessor :s2c_mac
  attr_accessor :session_id
 
  def read_byte
    proxy_read(1).ord
  end

  def read_uint32
    proxy_read(4).unpack('N').first
  end

  # RFC 4253 / 6.
  def read_packet
    packet_length = read_uint32
    padding_length = read_byte
    payload = proxy_read(packet_length - padding_length - 1).bytes
    padding = proxy_read(padding_length).bytes

    # RFC 4253 / 6.4.
    # we always have to keep track of the sequence number, but we only check
    # for the MAC if we've negotiated a method and the key
    @c2s_seq ||= 0
    if @c2s_mac
      mac = read(32).bytes

      # we have to reconstruct the packet back, due to the way in which i'm reading it
      msg  = ssh_uint32 @c2s_seq
      msg += ssh_uint32 packet_length
      msg += ssh_byte padding_length
      msg += payload
      msg += padding

      raise "invalid HMAC" if HMAC_SHA2_256(@c2s_mac, msg) != mac
    end
    @c2s_seq += 1
    
    payload
  end

  def send_packet payload
    # min of (8, cipher block size)
    # but like, we can just keep it at the cipher block size
    multiple = 16

    # 4 + 1 + payload.length + padding_length = 0 (mod multiple)
    # padding_length = - 5 - payload.length (mod multiple)
    padding_length = (- 5 - payload.length) % multiple
    padding_length += 16 # doesn't work without this, no idea why - todo
    packet_length  = payload.length + padding_length + 1

    packet  = ssh_uint32 packet_length
    packet += ssh_byte padding_length
    packet += payload
    packet += [0] * padding_length # Random.bytes(padding_length).bytes

    proxy_send packet

    # MAC stuff, look at the previous function
    # we're sending it after the rest of the packet, because it isn't encrypted
    # (and the proxy_send function encrypts everything)
    @s2c_seq ||= 0
    if @s2c_mac
      to_mac  = ssh_uint32 @s2c_seq
      to_mac += packet

      mac = HMAC_SHA2_256(@s2c_mac, to_mac)
      send mac.map(&:chr).join, 0
    end
    @s2c_seq += 1
  end
end

# those return byte arrays
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



# and now we can get into the actual protocol implementation

def handle_client cl
  begin
    # version exchange
    # todo not spec compliant
    client_id = cl.gets.delete_suffix("\r\n")
    puts client_id + " connected"
    cl.write ID_STRING + "\r\n"


    combined_payloads = algo_negotiation cl

    # since this is a toy implementation that only supports one algorithm for
    # everything, i don't have to pass the negotiated algos around - they're
    # always the same
    key_exchange cl, client_id, combined_payloads

    authenticate cl

    cl.read_packet.hexdump
  ensure
    cl.close
  end
end

# RFC 4253 / 7.
def algo_negotiation cl
  # let's prepare our packet first
  our_cookie = Random.bytes(16).bytes

  payload  = [20] # SSH_MSG_KEXINIT
  payload += our_cookie

  # those are our algorithm preferences
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
  # basically, we get a bunch of name_lists of the supported algorithms
  #
  # all we have to do in this implementation is to verify that the client
  # supports the algos which we use
  packet = cl.read_packet
  packet_copy = packet.dup

  assert packet.shift == 20 # SSH_MSG_KEXINIT
  client_cookie         = packet.shift 16


  # key exchange method
  assert packet.name_list.include? "diffie-hellman-group14-sha256"

  # server host key type
  assert packet.name_list.include? "ssh-rsa"

  # encryption algo
  assert packet.name_list.include? "aes256-ctr" # c2s
  assert packet.name_list.include? "aes256-ctr" # s2c

  # MAC algo
  assert packet.name_list.include? "hmac-sha2-256" # c2s
  assert packet.name_list.include? "hmac-sha2-256" # s2c

  # compression algo
  assert packet.name_list.include? "none" # c2s
  assert packet.name_list.include? "none" # s2c

  # we don't care about those
  _languages_c2s        = packet.name_list
  _languages_s2c        = packet.name_list


  first_kex_packet_follows = packet.shift != 0
  raise "unsupported" if first_kex_packet_follows # TODO

  _reserved = packet.uint32


  # ok, we've "negotiated" the algortihms used
  # one last thing - we return the combined client + server payloads
  # we need those in the key exchange

  ssh_string(packet_copy.map(&:chr).join) +
    ssh_string(payload.map(&:chr).join)
end

# RFC 3526 / 3.
# prime used for the DH key exchange
DH14P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

# RFC 4253 / 8.
# using diffie-hellman-group14-sha256
def key_exchange cl, client_id, combined_payloads
  ### 1. the client sends us E
  packet = cl.read_packet
  assert packet.shift == 30 # SSH_MSG_KEXDH_INIT
  e = packet.mpint # todo verify that e is in [1, p-1]


  ### 2. we send the client our host key, and do some crypto stuff
  payload = [31] # SSH_MSH_KEXDH_REPLY
  
  # encoded according to RFC 4253 / 6.6.
  encoded_host_key  = ssh_string "ssh-rsa"
  encoded_host_key += ssh_pmint HOST_KEY.params['e'].to_i
  encoded_host_key += ssh_pmint HOST_KEY.params['n'].to_i
  encoded_host_key  = encoded_host_key.map(&:chr).join # convert to string
  payload += ssh_string encoded_host_key

  # calculating the DH stuff
  y = rand(1..DH14P)
  f = 2.pow(y, DH14P)
  k = e.pow(y, DH14P)
  # and sending it
  payload += ssh_pmint f

  # and sending the signature
  # first we prepare the hash
  buf  = []
  buf += ssh_string client_id              # V_C
  buf += ssh_string ID_STRING              # V_S
  buf += combined_payloads                 # I_C || I_S
  buf += ssh_string encoded_host_key       # K_S
  buf += ssh_pmint e                       # e
  buf += ssh_pmint f                       # f
  buf += ssh_pmint k                       # K
  hash = SHA256 buf

  # then we prepare the signature
  # RFC 4253 / 6.6.
  signature  = ssh_string "ssh-rsa"
  signature += ssh_string rsa_sign hash
  signature  = signature.map(&:chr).join

  # and we append it to the payload
  payload   += ssh_string signature
 
  cl.send_packet payload


  # now the client should send SSH2_MSG_NEWKEYS
  packet = cl.read_packet
  assert packet == [21] # SSH_MSG_NEWKEYS

  # ok, we can also accept the new keys
  cl.send_packet [21]

  # and let's calculate the actual keys now / RFC 4253 / 7.2.
  cl.session_id = hash
  iv_c2s  = SHA256 ssh_pmint(k) + hash + ["A"] + cl.session_id
  iv_s2c  = SHA256 ssh_pmint(k) + hash + ["B"] + cl.session_id
  key_c2s = SHA256 ssh_pmint(k) + hash + ["C"] + cl.session_id
  key_s2c = SHA256 ssh_pmint(k) + hash + ["D"] + cl.session_id
  itg_c2s = SHA256 ssh_pmint(k) + hash + ["E"] + cl.session_id
  itg_s2c = SHA256 ssh_pmint(k) + hash + ["F"] + cl.session_id

  cl.c2s_cipher = AES256_ctr(key_c2s, iv_c2s)
  cl.c2s_mac = itg_c2s
  cl.s2c_cipher = AES256_ctr(key_s2c, iv_s2c)
  cl.s2c_mac = itg_s2c
end

def authenticate cl
  # at this point the client will probably send us an authentication request
  # i'm not sure if it can even send anything else, so i'll just panic if it does
  # as i always do in unexpected situations

  cl_payload = cl.read_packet
  assert cl_payload == ([5] + ssh_string("ssh-userauth"))
  #                      ^
  #                      SSH_MSG_SERVICE_REQUEST

  # ok, let's accept the service request
  cl.send_packet ([6] + ssh_string("ssh-userauth"))
  #                ^
  #                SSH_MSG_SERVICE_ACCEPT

  # and let's also send a banner, why not
  cl.send_packet ([53] + ssh_string("A banner message\n") + ssh_string("en"))
  #                ^
  #                SSH_MSG_USERAUTH_BANNER

  # the client send multiple auth requests
  loop do
    packet = cl.read_packet

    assert packet.shift == 50 # SSH_MSG_USERAUTH_REQUEST
    user    = packet.string
    service = packet.string
    method  = packet.string

    puts "#{user} logging in for #{service} via #{method}"

    if method == "publickey"
      signature_included = packet.shift
      algo = packet.string
      pubkey = packet.string

      fingerprint = Base64.encode64 pubkey
      puts algo + " " + fingerprint

      # let's assume that it's a valid key
      if signature_included > 0
        signature_blob = packet.string.bytes
        assert algo == signature_blob.string # the blob begins with the algo string
        signature = signature_blob.string.bytes # then the actual signature follows

        blob  = ssh_string cl.session_id.map(&:chr).join
        blob += [50]
        blob += ssh_string user
        blob += ssh_string service
        blob += ssh_string "publickey"
        blob += [1]
        blob += ssh_string algo
        blob += ssh_string pubkey

        pubkey = pubkey.bytes
        assert algo == pubkey.string

        e = pubkey.mpint
        n = pubkey.mpint

        assert rsa_verify n, e, blob, signature
        puts "key verified"
        cl.send_packet [52] # SSH_MSG_USERAUTH_SUCCESS
        break
      else
        # not fully tested, TODO
        # confirm that the key is ok
        response  = [60] # SSH_MSG_USERAUTH_PK_OK
        response += ssh_string algo
        response += ssh_string pubkey
        cl.send_packet response
        next
      end
    end

    response  = [51] # SSH_MSG_USERAUTH_FAILURE
    response += ssh_string "publickey"
    response += [0] # false
    cl.send_packet response
  end
end

STDOUT.sync = true
server = TCPServer.new 2020
loop do
  Thread.start(server.accept) {|c| handle_client c}
end

# todo list:
# create all the SSH_MSG contants
# ssh_namelist instead of the ssh_string hack
