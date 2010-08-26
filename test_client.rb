require 'test/unit'
require 'wowconnect'

class TestClient < Test::Unit::TestCase
  def setup
    @client = WOWConnect::Client.new("REDDRAGON010", "ECA16", "127.0.0.1")#"94.23.195.96")
  end
  
  def test_connect
    assert(@client.connect, "Login process failed")
    assert(@client.loggedin,"Not loggedin when supposed to")
  end
end