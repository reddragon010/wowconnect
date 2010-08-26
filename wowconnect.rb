require 'rubygems'
require 'bindata'
require 'socket'
require 'digest/sha1'
require 'digest/sha2'
require 'thread'

module WOWConnect
  ERROR_CODES = {
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

  class ALChallengeC < BinData::Record
    endian :little 
    uint8   :cmd, :value => 0
    uint8   :error, :value => 8
    uint16  :psize, :initial_value => lambda { 30 + l_len}
    string  :gamename, :length => 4
    uint8   :version1, :initial_value => 3
    uint8   :version2, :initial_value => 3
    uint8   :version3, :initial_value => 2
    uint16  :build, :initial_value => 11403
    string  :platform, :length => 4
    string  :os, :length => 4
    string  :country, :length => 4
    uint32  :timezone_bias, :initial_value => 4294966876
    array   :ip, :type => :uint8, :initial_length => 4
    uint8   :l_len
    string  :l, :length => lambda { l_len }
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

  class ALChallengeS < BinData::Record
    endian :little 
    uint8   :cmd, :value => 0
    uint8   :unk2, :value => 8
    uint8   :error
    string  :srp_b, :length => 32, :onlyif => :is_ok?
    uint8   :srp_g_len, :initial_value => 1, :onlyif => :is_ok?
    uint8   :srp_g, :onlyif => :is_ok?
    uint8   :srp_n_len, :initial_value => 32, :onlyif => :is_ok?
    string  :srp_n, :length => 32, :onlyif => :is_ok?
    string  :srp_s, :length => 32, :onlyif => :is_ok?
    string  :unk3, :length => 16, :onlyif => :is_ok?

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

  class ALProofC < BinData::Record
    endian :little 
    uint8   :cmd, :value => 1
    string  :a, :length => 32
    string  :m1, :length => 20
    array  :crc_hash, :type => :uint8 ,:initial_length => 20
    uint8   :number_of_keys, :value => 0
    uint8   :securityFlags, :value => 0
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

  class ALProofS < BinData::Record
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
  
  class Client
    attr_reader :loggedin
    
    def initialize(user,pass,host,port=3724)
      @host = host
      @port = port
      @username = user
      @password = pass
      @k = 3
      @loggedin = false
    end
    
    def connect
      puts "Connecting to #{@host}:#{@port}..."
      @socket = TCPSocket.new(@host,@port)
      puts "connected sending Challenge"
      alc = gen_alchallenge
      @socket.puts(alc.to_binary_s)
      read_alchallenge
      puts "challenge received:"
      puts "salt=#{@salt}"
      puts "B=#{@B}"
      puts "g=#{@g}"
      puts "N=#{@N}"
      puts "building proof..."
      init_alproof
      alp = gen_alproof
      puts "x=#{@x}"
      puts "v=#{@v}"
      puts "a=#{@a}" 
      puts "A=#{@A}" 
      puts "u=#{@u}" 
      puts "s=#{@s}" 
      puts "S=#{@S}" 
      puts "m1=#{@m1}"
      puts "m2=#{@m2}"
      @socket.puts(alp.to_binary_s)
      sleep 5
      read_alproof
      @socket.close
      return true
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
    
    def gen_alchallenge
      alc = ALChallengeC.new
      alc.gamename = 'WOW'
      alc.platform = '68x'
      alc.os = 'XSO'
      alc.country = 'EDed'
      alc.ip = local_ip
      alc.l_len = @username.size
      alc.l = @username
      return alc
    end
    
    def read_alchallenge
      alc = ALChallengeS.new
      alc.read(@socket.read)
      if alc.error == 0
        @salt = alc.srp_s.to_hexstring
        @B = alc.srp_b.to_hexstring
        @g = alc.srp_g.to_i
        @N = alc.srp_n.to_hexstring
      else
        throw ERROR_CODES.index(alc.error).to_s
      end
    end
    
    def init_alproof
      @x = gen_x(@username,@password,@salt)
      @v = gen_v(@g,@x,@N)
      @a = gen_rand_a
      @A = gen_a(@g,@a,@N)
      @u = gen_u(@A,@B)
      @s = gen_s(@B,@k,@g,@x,@N,@a,@u)
      @S = gen_ss(@s)
      @m1 = gen_m1(@N,@g,@username,@salt,@A,@B,@S)
      @m2 = gen_m2(@A,@m1,@S)
    end
    
    def gen_alproof
      alp = ALProofC.new
      alp.cmd = 1
      alp.a = @A.to_bytearray
      alp.m1 = @m1.to_bytearray
      return alp
    end
    
    def read_alproof
      alp = ALProofS.new
      alp.read(@socket.read)
      if alp.error == 0
        @m2 = get_hash(alp.m2)
        @loggedin = true
      else
        throw ERROR_CODES.index(alp.error).to_s
      end
    end
    
    def gen_x(user,pass,salt)
      userhash = Digest::SHA1.new
      xhash = Digest::SHA1.new
      userhash.update(user + ':' + pass)
      xhash.update(salt.to_bytearray)
      xhash.update(userhash.digest)
      return xhash.hexdigest
    end
    
    def gen_v(g,x,n)
      return g.modexp(x.to_integer,n.to_integer).to_s(16)
    end
    
    def gen_rand_a
      erg = ""
      (0..19).each do |e|
        erg += Kernel.rand(255).to_s(16)
      end
      return erg
    end
    
    def gen_a(g,rand_a,n)
      return g.modexp(rand_a.to_integer,n.to_integer).to_s(16)
    end
    
    def gen_u(aa,bb)
      uhash = Digest::SHA1.new
      uhash.update(aa.to_bytearray)
      uhash.update(bb.to_bytearray)
      return uhash.hexdigest
    end
    
    def gen_s(bb,k,g,x,n,a_rand,u)
      return (bb.to_integer - k * g.modexp(x.to_integer,n.to_integer)).modexp((a_rand.to_integer + u.to_integer * x.to_integer),n.to_integer).to_s(16)
    end
    
    def gen_ss(s)
      rev_s = s.to_integer_reverse.to_s(16)
      puts "rev_s=" + rev_s
      s1 = ""
      s2 = ""

      i = 0
      (0..15).each do |e|
        s1 += rev_s[e*4..e*4+1]
        s2 += rev_s[e*4+2..e*4+3]
        i = i + 4
      end

      s1hash = Digest::SHA1.hexdigest(s1.to_bytearray)
      s2hash = Digest::SHA1.hexdigest(s2.to_bytearray)

      sshash = ""
      (0..19).each do |e|
        sshash += s1hash[e*2..e*2+1]
        sshash += s2hash[e*2..e*2+1]
        i = i + 4
      end
      return sshash
    end
    
    def gen_m1(n,g,user,salt,aa,bb,ss)
      nhash = Digest::SHA1.hexdigest(n.to_bytearray)
      ghash = Digest::SHA1.hexdigest(g.to_s(16).to_bytearray)

      userhash = Digest::SHA1.hexdigest(user.upcase)

      nhash_ba = nhash.to_bytearray
      ghash_ba = ghash.to_bytearray
      nghash = ""
      (0..19).each{ |i| nghash += [(nhash_ba[i] ^ ghash_ba[i])].pack('C*')}

      temp = nghash.to_hexstring + userhash + salt + aa + bb + ss 

      m1 = Digest::SHA1.hexdigest(temp.to_bytearray)
      return m1
    end
    
    def gen_m2(aa,m1,ss)
      temp = aa.to_bytearray + m1.to_bytearray + ss.to_bytearray 
      m2 = Digest::SHA1.hexdigest(temp)
    end
  end
  
  class Server
    
    def initialize(port=3724)
      @port = port
      @N = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7'
      @g = 7 
      @k = 3
    end
    
    def startup
      puts "Starting server..."
      @server = TCPServer.new(@port)
      puts "Server started at #{@port}"
      while (session = @server.accept)
        Thread.start do
          puts "Connection from #{session.peeraddr[2]} at #{session.peeraddr[3]}"
          puts "Receiving Challenge ..."
          read_alchallenge(session)
          get_password
          init_alchallenge
          alc = gen_alchallenge
          puts "Creating/Sending Challenge-Response..."
          session.puts(alc.to_binary_s)
          puts "response sent"
          
          
          session.close
        end 
      end
    end
    
    def read_alchallenge(session)
      alc = ALChallengeC.new
      alc.read(session.gets)
      puts "User #{alc.l} is trying to login"
      @username = alc.l
    end
    
    def get_password
      @password = "ECA16"
    end
    
    def init_alchallenge
      @salt = gen_salt
      @b = gen_b
      @x = gen_x(@username,@password,@salt)
      @v = gen_v(@g,@x,@N)
      @B = gen_bb(@k,@v,@g,@b,@N)
    end
    
    def gen_alchallenge
      alc = ALChallengeS.new
      alc.error = 0
      alc.srp_b = @B
      alc.srp_g = @g
      alc.srp_n = @N
      alc.srp_s = @salt
      return alc
    end
    
    def gen_salt
      return '33f140d46cb66e631fdbbbc9f029ad8898e05ee533876118185e56dde843674f'
    end
    
    def gen_b
      return '8692E3A6BA48B5B1004CEF76825127B7EB7D1AEF'
    end
    
    def gen_x(user,pass,salt)
      userhash = Digest::SHA1.new
      xhash = Digest::SHA1.new
      userhash.update(user + ':' + pass)
      xhash.update(salt.to_bytearray)
      xhash.update(userhash.digest)
      return xhash.hexdigest
    end
    
    def gen_v(g,x,n)
      return g.modexp(x.to_integer_reverse,n.to_integer_reverse).to_s(16)
    end

    def gen_bb(k,v,g,b,n)
      temp1 = k * v.to_integer 
      temp2 = g.modexp(b.to_integer_reverse,n.to_integer_reverse) 
      temp3 = temp1 + temp2 
      return (temp3 % n.to_integer_reverse).to_s(16).to_bytearray.reverse.to_hexstring
    end
    
    def gen_rand_a()
      erg = ""
      (0..19).each do |e|
        erg += Kernel.rand(255).to_s(16)
      end
      return erg
    end
    
    def gen_a(g,rand_a,n)
      return g.modexp(rand_a.to_integer,n.to_integer)
    end
    
    def gen_u(aa,bb)
      uhash = Digest::SHA1.new
      uhash.update(aa.to_bytearray)
      uhash.update(bb.to_bytearray)
      return uhash.hexdigest
    end
    
    def gen_s(v,u,n,aa,b)
      temp = v.to_integer.modexp(u.to_integer_reverse,n.to_integer_reverse) * aa.to_integer_reverse
      return temp.modexp(b.to_integer_reverse,n.to_integer_reverse).to_s(16)
    end
    
    def gen_ss(s)
      rev_s = s.to_integer_reverse.to_s(16)
      s1 = ""
      s2 = ""

      i = 0
      (0..15).each do |e|
        s1 += rev_s[e*4..e*4+1]
        s2 += rev_s[e*4+2..e*4+3]
        i = i + 4
      end

      s1hash = Digest::SHA1.hexdigest(s1.to_bytearray)
      s2hash = Digest::SHA1.hexdigest(s2.to_bytearray)

      sshash = ""
      (0..19).each do |e|
        sshash += s1hash[e*2..e*2+1]
        sshash += s2hash[e*2..e*2+1]
        i = i + 4
      end
      return sshash
    end
    
    def gen_m1(n,g,user,salt,aa,bb,ss)
      nhash = Digest::SHA1.hexdigest(n.to_bytearray)
      ghash = Digest::SHA1.hexdigest(g.to_bytearray)

      userhash = Digest::SHA1.hexdigest(user.upcase)
  
      nhash_ba = nhash.to_bytearray
      ghash_ba = ghash.to_bytearray
      nghash = ""
      (0..19).each{ |i| nghash += [(nhash_ba[i] ^ ghash_ba[i])].pack('C*')}
    
      temp = nghash.to_hexstring + userhash + salt + aa + bb + ss 
    
      m1 = Digest::SHA1.hexdigest(temp.to_bytearray)
      return m1
    end
    
    def gen_m2(aa,m1,ss)
      temp = aa.to_bytearray + m1.to_bytearray + ss.to_bytearray 
      m2 = Digest::SHA1.hexdigest(temp)
    end
  end
end

# Some changes on the coretypes for easier / more readable code
class String
  def to_bytearray
    size = self.size / 2
    self.unpack('a2'*size).map{|x| x.hex}.pack('c'*size)
  end
  def to_hexstring
    self.unpack('H*')[0]
  end
  def to_integer
    Integer.from_unsigned_bytes(self.to_bytearray)
  end
  def to_integer_reverse
    Integer.from_unsigned_bytes(self.to_bytearray.reverse)
  end
end
class Integer
  def self.from_unsigned_bytes(bytes)
    bytes = bytes.to_str
    n = 0
    bytes.each_byte do |b|
      n <<= 8
      n |= b
    end
    n
  end

  def modexp(exp, n)
    # x ** b mod n
    x = self.to_int
    b = exp.to_int
    n = n.to_int
    z = 1
    (n.bit_size - 1).downto(0) do |i|
      z = z ** 2 % n
      if b[i] == 1 then
        z = z * x % n
      end
    end
    z
  end

  def bit_size
    i = self.to_int
    hibit = i.size * 8 - 1
    while( i[hibit] == 0 ) do
      hibit = hibit - 1
      break if hibit < 0
    end
    hibit + 1
  end

  def []=(position, value)
    bit = 2 ** position
    i = self.to_int
    if value
      i |= bit
    else
      i &= ~bit
    end
    i
  end
end
