require 'rubygems'
require 'bindata'
require 'socket'
require 'digest/sha1'

error_codes = {
:REALM_AUTH_SUCCESS => 0,                                   # Success
:REALM_AUTH_FAILURE => 0x01,                                # Unable to connect
:REALM_AUTH_UNKNOWN1 => 0x02,                               # Unable to connect
:REALM_AUTH_ACCOUNT_BANNED => 0x03,                         # This <game> account has been closed and is no longer available for use. Please go to <site>/banned.html for further information.
:REALM_AUTH_NO_MATCH => 0x04,                               # The information you have entered is not valid. Please check the spelling of the account name and password. If you need help in retrieving a lost or stolen password, see <site> for more information
:REALM_AUTH_UNKNOWN2 => 0x05,                               # The information you have entered is not valid. Please check the spelling of the account name and password. If you need help in retrieving a lost or stolen password, see <site> for more information
:REALM_AUTH_ACCOUNT_IN_USE => 0x06,                         # This account is already logged into <game>. Please check the spelling and try again.
:REALM_AUTH_PREPAID_TIME_LIMIT => 0x07,                     # You have used up your prepaid time for this account. Please purchase more to continue playing
:REALM_AUTH_SERVER_FULL => 0x08,                            # Could not log in to <game> at this time. Please try again later.
:REALM_AUTH_WRONG_BUILD_NUMBER => 0x09,                     # Unable to validate game version. This may be caused by file corruption or interference of another program. Please visit <site> for more information and possible solutions to this issue.
:REALM_AUTH_UPDATE_CLIENT => 0x0a,                          # Downloading
:REALM_AUTH_UNKNOWN3 => 0x0b,                               # Unable to connect
:REALM_AUTH_ACCOUNT_FREEZED => 0x0c,                        # This <game> account has been temporarily suspended. Please go to <site>/banned.html for further information
:REALM_AUTH_UNKNOWN4 => 0x0d,                               # Unable to connect
:REALM_AUTH_UNKNOWN5 => 0x0e,                               # Connected.
:REALM_AUTH_PARENTAL_CONTROL => 0x0f
}
################
# Client->Server AUTH_LOGON_CHALLENGE
# cmd           uint8         0x00
# error         uint8         0x08
# size          uint16        0x38
# gamename      uint8[4]      WOW
# version1      uint8         0x03
# version2      uint8         0x01
# version3      uint8         0x03
# build         uint16        0xDB26 (9974)
# platform      uint8[4]      68x
# os            uint8[4]      XOS
# country       uint8[4]      EDed
# timezone_bias uint32        0x3C000000
# ip            uint32[4]     0x0A000002
# l_len         uint8         0x08
# l             uint8[l_len]  TESTCHAR

class Client_ALC < BinData::Record
  endian :little 
  uint8   :cmd, :value => 0
  uint8   :error, :value => 8
  uint16  :psize, :value => lambda { 30 + l_len}
  string  :gamename, :length => 4
  uint8   :version1, :value => 3
  uint8   :version2, :value => 3
  uint8   :version3, :value => 2
  uint16  :build, :value => 11403
  string  :platform, :length => 4
  string  :os, :length => 4
  string  :country, :length => 4
  uint32  :timezone_bias, :value => 4294966876
  array   :ip, :type => :uint8, :initial_length => 4
  uint8   :l_len, :value => lambda { l.num_bytes }
  string  :l
end
#####################

################
# Server->Client AUTH_LOGON_CHALLENGE
# cmd           uint8         0x00
# error         uint8         0x00
# srp_b         uint32        0c:f0:5f:a0:03:0b:37:8e:e5:ea:92:94:8e:57:1e:d5:dc:33:97:84:ba:55:19:00:d8:7b:68:0c:e8:2e:b1:1b
# srp_g_len     uint8         0x01
# srp_g         uint8         0x07
# srp_n_len     uint32        0x20
# srp_n         uint32[20]    0xB79B3C2A87823CAB8F5EBFBF8CA10108535006298B5ABDBD5E53A1895C644F89
# srp_s         uint32[20]    0xA648CE567D7B6A7876BFDC76A8A256CB900FAF57E7BC946303765CA8BC87C621

class Server_ALC < BinData::Record
  endian :little 
  uint8   :cmd
  uint8   :unk2
  uint8   :error
  array   :srp_b, :type => :uint8, :initial_length => 32, :onlyif => :is_ok?
  uint8   :srp_g_len, :onlyif => :is_ok?
  uint8   :srp_g, :onlyif => :is_ok?
  uint8   :srp_n_len, :onlyif => :is_ok?
  array   :srp_n, :type => :uint8, :initial_length => 32, :onlyif => :is_ok?
  array   :srp_s, :type => :uint8, :initial_length => 32, :onlyif => :is_ok?
  array   :unk3, :type => :uint8, :initial_length => 16, :onlyif => :is_ok?
  
  def is_ok?
    error == 0
  end
end
#####################

################
# Client->Server AUTH_LOGON_PROOF
# cmd             uint8         0x00
# A[32]           uint8
# M1[20]          uint8
# crc_hash[20]    uint8
# number_of_keys  uint8
# securityFlags   uint8

class Client_ALP < BinData::Record
  endian :little 
  uint8   :cmd
  array   :a, :type => :uint8, :initial_length => 32
  array   :m1, :type => :uint8, :initial_length => 20
  array   :crc_hash, :type => :uint8, :initial_length => 20
  uint8   :number_of_keys
  uint8   :securityFlags
end
#####################

################
# Server->Client AUTH_LOGON_PROOF
# cmd             uint8         0x00
# A[32]           uint8
# M1[20]          uint8
# crc_hash[20]    uint8
# number_of_keys  uint8
# securityFlags   uint8

class Server_ALP < BinData::Record
  endian :little 
  uint8   :cmd
  uint8   :error
  array   :m2, :type => :uint8, :initial_length => 20, :onlyif => :is_ok?
  uint32  :unk1, :onlyif => :is_ok?
  uint32  :unk2, :onlyif => :is_ok?
  uint16  :unk3, :onlyif => :is_ok?
  
  def is_ok?
    error == 0
  end
end
#####################

def get_hash(bytearray)
  op = ""
  bytearray.each do |i|
    hex = i.to_i.to_s(16).upcase
    if i.to_i > 15
      op += hex
    else
      op += '0' + hex
    end 
  end
  return op
end

def local_ip
  orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
  UDPSocket.open do |s|
    s.connect '64.233.187.99', 1
    s.addr.last.split('.').map{|i| i.to_i}
  end
ensure
  Socket.do_not_reverse_lookup = orig
end

def generate_client_alc(username)
  alc = Client_ALC.new
  alc.gamename = 'WOW'
  alc.platform = '68x'
  alc.os = 'XSO'
  alc.country = 'EDed'
  alc.ip = local_ip
  alc.l = username
  return alc
end

# Config
host = "94.23.195.96"
port = 3724
username = 'REDDRAGON010'
password = 'password'

#Init
alc = generate_client_alc(username)
puts alc.inspect
s_alc = Server_ALC.new
socket = TCPSocket.new(host,port)

#Send AUTH_LOGON_CHALLANGE_C to server
socket.puts(alc.to_binary_s)
#Get AUTH_LOGON_CHALLANGE_S from server
s_alc.read(socket.read)
#Throw Error on Error :P
unless s_alc.error == 0
  throw error_codes.index(s_alc.error).to_s
end

puts s_alc.inspect

authstr = "#{username}:#{password}"
userhash = Digest::SHA1.hexdigest(authstr).upcase

puts "SRP_B:" + get_hash(s_alc.srp_b)
puts "SRP_G:" + s_alc.srp_g.to_i.to_s(16)
puts "SRP_N:" + get_hash(s_alc.srp_n)
puts "SRP_S:" + get_hash(s_alc.srp_s)

salt = get_hash(s_alc.srp_s)

puts "UserHash:" + userhash
xhash = Digest::SHA1.hexdigest(salt + userhash)
puts xhash


#Cleanup
socket.close
