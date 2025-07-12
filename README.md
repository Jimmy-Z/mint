### mint is not a tunnel
it looks like one at a glance, but it's not.
nowadays virtually all traffic on the Internet is TLS already,
there's no point in wrapping them in TLS (or whatever) again.

handshake and a couple following packets are encrypted, for obfuscation.
after that, it's just plain TCP.

in an eye-balling test, it consumes about 1/3 CPU compared to stunnel under the same load.

so far it's just a PoC.

### to do
 - [ ] timeout in handshake
 - [ ] 