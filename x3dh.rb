require 'openssl'
require 'rbnacl'

module X3DH
  def generate_key_pair
    key = RbNaCl::PrivateKey.generate
    [key, key.public_key]
  end

  # key1: X25519形式の秘密鍵
  # key2: X25519形式の公開鍵
  def dh(key1, key2)
    RbNaCl::GroupElement.new(key2).mult(key1)
  end

  def hkdf_sha256(km, n)
    ikm = ['ff' * 32].pack('H*') + km
    opt = {
        salt: ['00' * 32].pack('H*'),
        info: "MyProtocol key#{n + 1}".unpack1('H*'),
        length: 32,
        hash: 'SHA256'
    }
    OpenSSL::KDF.hkdf(ikm, **opt)
  end

  def encrypt(key, plaintext, ad)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
    nonce = RbNaCl::Random.random_bytes(cipher.nonce_bytes)
    [cipher.encrypt(nonce, plaintext, ad), nonce]
  end

  def decrypt(key, ciphertext, ad, nonce)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
    cipher.decrypt(nonce, ciphertext, ad)
  end
end

module KeyEncoder
  # 曲線の種類（X25519またはX448）を表す1バイトの定数とRFC7748で規定されている。
  # u座標のリトルエンディアンエンコードが推奨されている。今回はこれだけよい。
  def self.encode(key)
    # X25519は1、X448は2とする
    '1' + key.to_bytes
  end
end

module RFC7748Encoder
  # RFC7748で示されている整数とバイトシーケンスの相互変換は以下の通り。
  # 今回の実行環境では上記の KeyEncoder.encode と同じ結果になる。

  # RFC7748で示されている decodeLittleEndian のRuby板
  def self.decode_little_endian(b, bits = 255)
    # バイトシーケンスを連結して1つの整数にする
    (0...((bits + 7) / 8)).reduce(0) { |sum, i| sum + (b[i].ord << (8 * i)) }
  end

  # RFC7748で示されている decodeUCoordinate のRuby板
  # 入力として与えられた32バイトのバイトシーケンスを同じバイト数の整数に変換する
  def self.decode_u_coordinate(u, bits = 255)
    u_list = u.bytes
    # 使われないビットを無視する
    if bits % 8 != 0
      u_list[-1] &= (1 << (bits % 8)) - 1
    end
    decode_little_endian(u_list, bits)
  end

  # RFC7748で示されている encodeUCoordinate のRuby板
  # 入力として与えられた32バイトの整数を同じバイト数のバイトシーケンスに変換する
  def self.encode_u_coordinate(u, bits = 255)
    p = 2 ** 255 - 19 # X25519形式で固定している
    u = u % p
    (0...((bits + 7) / 8)).map { |i| (u >> (8 * i)) & 0xff }.pack("C*")
  end
end

class Person
  include X3DH

  def initialize
    init_keys
  end

  def init_keys
    @ik, @ik_pub = generate_key_pair
    @spk, @spk_pub = generate_key_pair

    @sk = RbNaCl::SigningKey.generate
    @sk_pub = @sk.verify_key
    @spk_signature = @sk.sign(KeyEncoder.encode(@spk_pub))

    @opk_set, @opk_pub_set =
        100.times.map { generate_key_pair }.flatten.partition.with_index { |_, i| i.even? }
  end

  def prekey_bundle
    {
        ik_pub: @ik_pub.to_bytes,
        sk_pub: @sk_pub.to_bytes,
        spk_pub: @spk_pub.to_bytes,
        spk_signature: @spk_signature,
        opk_pub_set: @opk_pub_set.map(&:to_bytes)
    }
  end

  def init_x3dh_initiator(prekey_bundle)
    bundle = {
        ik_pub: RbNaCl::PublicKey.new(prekey_bundle[:ik_pub]),
        sk_pub: RbNaCl::VerifyKey.new(prekey_bundle[:sk_pub]),
        spk_pub: RbNaCl::PublicKey.new(prekey_bundle[:spk_pub]),
        spk_signature: prekey_bundle[:spk_signature],
        opk_id: prekey_bundle[:opk_id],
        opk_pub: RbNaCl::PublicKey.new(prekey_bundle[:opk_pub])
    }

    # X3DH以降の通信でも必要になる
    @spk_pub = bundle[:spk_pub]

    begin
      bundle[:sk_pub].verify(bundle[:spk_signature], KeyEncoder.encode(@spk_pub))
    rescue RbNaCl::BadSignatureError => e
      raise e.inspect
    end

    ek, ek_pub = generate_key_pair

    dh1 = dh(@ik, @spk_pub)
    dh2 = dh(ek, bundle[:ik_pub])
    dh3 = dh(ek, @spk_pub)
    dh4 = dh(ek, bundle[:opk_pub])
    @sk = hkdf_sha256([dh1, dh2, dh3, dh4].map(&:to_bytes).join, 0)
    @ad = KeyEncoder.encode(@ik_pub) + KeyEncoder.encode(bundle[:ik_pub])

    ciphertext, nonce = encrypt(@sk, 'Initial message', @ad)

    {
        ik_pub: @ik_pub,
        ek_pub: ek_pub,
        opk_id: bundle[:opk_id],
        message: ciphertext,
        nonce: nonce
    }
  end

  def init_x3dh_responder(data)
    data[:ik_pub] = RbNaCl::PublicKey.new(data[:ik_pub])
    data[:ek_pub] = RbNaCl::PublicKey.new(data[:ek_pub])
    opk = @opk_set[data[:opk_id]]

    dh1 = dh(@spk, data[:ik_pub])
    dh2 = dh(@ik, data[:ek_pub])
    dh3 = dh(@spk, data[:ek_pub])
    dh4 = dh(opk, data[:ek_pub])
    @sk = hkdf_sha256([dh1, dh2, dh3, dh4].map(&:to_bytes).join, 0)
    @ad = KeyEncoder.encode(data[:ik_pub]) + KeyEncoder.encode(@ik_pub)

    {message: decrypt(@sk, data[:message], @ad, data[:nonce])}
  end

  def send_message(msg)
    ciphertext, nonce = encrypt(@sk, msg, @ad)
    [{nonce: nonce}, ciphertext]
  end

  def receive_message(header, ciphertext)
    decrypt(@sk, ciphertext, @ad, header[:nonce])
  end
end

class Server
  # 何らかの通信路を通るのであればbase64形式でエンコードするのが望ましい
  def upload(**data)
    @data = data
  end

  def download
    {
        ik_pub: @data[:ik_pub],
        sk_pub: @data[:sk_pub],
        spk_pub: @data[:spk_pub],
        spk_signature: @data[:spk_signature],
        opk_id: 0,
        opk_pub: @data[:opk_pub_set][0]
    }
  end
end

if __FILE__ == $0
  server = Server.new
  alice = Person.new
  bob = Person.new

  # 形式上、公開鍵はサーバーで保存される
  server.upload(**bob.prekey_bundle)
  prekey_bundle = server.download

  x3dh_data = alice.init_x3dh_initiator(prekey_bundle)
  bob.init_x3dh_responder(x3dh_data)

  a1 = alice.send_message('a1')
  puts bob.receive_message(*a1)
  b1 = bob.send_message('b1')
  puts alice.receive_message(*b1)

  a2 = alice.send_message('a2')
  puts bob.receive_message(*a2)
  b2 = bob.send_message('b2')
  puts alice.receive_message(*b2)
end
