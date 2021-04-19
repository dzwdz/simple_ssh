class String
  def bytes
    each_char.map(&:ord)
  end
end


class Array
  # does a hexdump that looks like the OpenSSL dumps
  def hexdump
    pos = 0
    each_slice(16) do |s|
      print pos.to_s.rjust 4
      print ": "

      s.each {|d| print d.to_s(16).rjust(2, '0') + " "}
      print " "

      s.each do |d|
        c = d.chr
        if c =~ /[^[:print:]]/
          print '.'
        else
          print c
        end
      end

      puts
      pos += 16
    end
  end

  # parses a byte array, most significant byte first
  def to_i
    val = 0
    each {|d| val = val * 256 + d}
    val
  end
end

def assert val
  raise "assertion failed" unless val
end
