Ruby implementation of The X3DH Key Agreement Protocol.

## Usage

```ruby
bundle install
bundle exec ruby x3dh.rb
```

Or

```ruby
server = Server.new
alice = Person.new
bob = Person.new

server.upload(**bob.prekey_bundle)
prekey_bundle = server.download

x3dh_data = alice.init_x3dh_sender(prekey_bundle)
bob.init_x3dh_receiver(x3dh_data)

a1 = alice.send_message('a1')
puts bob.receive_message(*a1)

b1 = bob.send_message('b1')
puts alice.receive_message(*b1)
```

