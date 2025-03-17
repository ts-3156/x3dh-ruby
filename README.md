A Ruby implementation of The X3DH Key Agreement Protocol.

As much as possible, I have implemented it as described in the official Signal documentation.

This code snippet is written in very small Ruby code. If you want to implement X3DH in your preferred programming language,
it is better to look directly at the Ruby code.

## Usage

```shell
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
```

## Different languages

Ruby version https://github.com/ts-3156/x3dh-ruby

JavaScript version https://github.com/ts-3156/x3dh-javascript

TypeScript version https://github.com/ts-3156/x3dh-typescript

## Official documentation

https://signal.org/docs/specifications/x3dh/

