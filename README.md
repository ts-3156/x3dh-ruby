A Ruby implementation of The X3DH Key Agreement Protocol.

This application is written in very small Ruby code. If you want to implement X3DH in your preferred programming language, it is better to look directly at the Ruby code.

## Usage

```ruby
bundle install
bundle exec ruby x3dh.rb
```

Or

```ruby
require_relative 'x3dh'

server = Server.new
alice = Person.new
bob = Person.new

server.upload(**bob.prekey_bundle)
prekey_bundle = server.download

x3dh_data = alice.init_x3dh_sender(prekey_bundle)
bob.init_x3dh_recipient(x3dh_data)

a1 = alice.send_message('a1')
puts bob.receive_message(*a1)

b1 = bob.send_message('b1')
puts alice.receive_message(*b1)
```

## Documentation

https://signal.org/docs/specifications/x3dh/

