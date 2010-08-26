require 'test/unit'
require 'wowconnect'

class TestServerDry < Test::Unit::TestCase
  def setup
    @user = 'TEST'
    @pass = 'TEST'
    @salt = '33f140d46cb66e631fdbbbc9f029ad8898e05ee533876118185e56dde843674f'
    @n = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7'
    @k = 3
    @g = 7
    @b = "8692E3A6BA48B5B1004CEF76825127B7EB7D1AEF"
    @a = '5d5e33d2ecc01834ab547b28712bb79ba652922b6063c63d2b061364c50ec67b'

    @bb = '645d1f78973073701e12bc98aa38ea99b4bc435c32e8447c73ab077ae4d75964'
    @aa = '232fb1b88529643d95b8dce78f2750c75b2df37acba873eb31073839eda0738d'
    @m1= 'eeb4adca80f4de02f9a9fe8d000d682e3ddfad6f'
    
    @x = '1b70dd2ad03c1ed140223f8f8741c00ec3a4ce73'
    @v = '996ec7b349d5827043ecd0e6efba3daea5590f944d0184fee1b83ff4f59ecfa8'
    @u = '2f4969ac9f387fd672236f9491a516777cdde1c1'
    @s = '7666dc8a226dd0e3de093dddf6bc2b7929df2936a8cf15a972de4042766380ba'
    @ss = '0261f4eb4891b66a1a826eb77928d864b7ea145438db7cfd0d3d2fc022cecc468379f2c087787f14'
    
    @m2 = '3a92ed0b783597be95654d6c66442046f9d389ae'
    
    @server = WOWConnect::Server.new
  end

  # def teardown
  # end
  
  def test_gen_x
    assert(@x == @server.gen_x(@user,@pass,@salt))
  end
  
  def test_gen_v
    assert(@v == @server.gen_v(@g,@x,@n))
  end
  
  def test_gen_bb
    assert(@bb == @server.gen_bb(@k,@v,@g,@b,@n))
  end
  
  def test_gen_u
    assert(@u == @server.gen_u(@aa,@bb))
  end
  
  def test_gen_s
    assert(@s == @server.gen_s(@v,@u,@n,@aa,@b))
  end
  
  def test_gen_m1
    assert(@m1 == @server.gen_m1(@n,"07",@user,@salt,@aa,@bb,@ss))
  end
  
  def test_gen_m2
    assert(@m2 == @server.gen_m2(@aa,@m1,@ss))
  end
end