### mint is not a tunnel
it looks like one at a glance, but it's not.
nowadays virtually all traffic on the Internet is TLS already,
there's no point in wrapping them in TLS (or whatever) again.

handshake stage is encrypted, for obfuscation.
after that, it's just plain TCP.
should be beneficial for low power devices.
