module RFC7748Encoder
  # The interconversion between integer and byte sequence shown in RFC7748 is as follows.
  # In my runtime environment (OS X), the result is the same as KeyEncoder.encode implemented in x3dh.rb.
  # https://www.ietf.org/rfc/rfc7748.txt

  # A Ruby implementation of decodeLittleEndian as shown in RFC7748
  def self.decode_little_endian(b, bits = 255)
    # Convert a byte sequence to one large integer.
    (0...((bits + 7) / 8)).reduce(0) { |sum, i| sum + (b[i].ord << (8 * i)) }
  end

  # A Ruby implementation of decodeUCoordinate as shown in RFC7748
  # A byte sequence -> an integer of the same number of bytes
  def self.decode_u_coordinate(u, bits = 255)
    u_list = u.bytes
    # Ignore any unused bits.
    if bits % 8 != 0
      u_list[-1] &= (1 << (bits % 8)) - 1
    end
    decode_little_endian(u_list, bits)
  end

  # A Ruby implementation of encodeUCoordinate as shown in RFC7748
  # An integer of the same number of bytes -> a byte sequence
  def self.encode_u_coordinate(u, bits = 255)
    p = 2 ** 255 - 19 # Fixed in X25519 format.
    u = u % p
    (0...((bits + 7) / 8)).map { |i| (u >> (8 * i)) & 0xff }.pack("C*")
  end
end
