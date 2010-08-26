require 'test/unit'
require 'wowconnect'

class TestServer < Test::Unit::TestCase
  def setup
    @server = WOWConnect::Server.new
  end
  
  def test_startup
    @server.startup
  end
end