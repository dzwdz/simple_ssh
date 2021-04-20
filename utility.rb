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

  # increments a MSB byte array in-place
  def increment
    i = length - 1
    while i >= 0
      self[i] += 1
      break unless self[i] > 255
      self[i] = 0
      i -= 1
    end
  end

  # xors an array with an enumerator
  # this implementation is a bit dumb, it's a ruby bug workaround
  def xor(b)
    map {|x| x ^ b.next}
  end

  # copypasted from https://stackoverflow.com/a/5609035
  def rjust(n, x); Array.new([0, n-length].max, x)+self end
  def ljust(n, x); dup.fill(x, length...n) end
end

def assert val
  raise "assertion failed" unless val
end
