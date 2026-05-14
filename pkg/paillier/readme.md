# What is paillier
Paillier is an asymmetric encryption scheme that is homomorphic. You can encrypt numbers with a public key, decrypt with a private key, and perform addition on encrypted values without decrypting them.

# why is it useful in MPC?
Because you can compute on encrypted data. Two parties can add their secret numbers together without revealing them to each other.
```
Encrypt(x) * Encrypt(y) mod N² = Encrypt(x + y)
Encrypt(x)^k mod N²            = Encrypt(x * k)
```

# how are the keys generated?
```
1- choose p and q (large primes)
2- N = p * q
3- N² = N * N  (this is the working modulus, unlike RSA which uses N)
4- lambda = lcm(p-1, q-1)  (like RSA's φ(n) but using lcm instead of multiply)
5- g = N + 1  (standard simplification for the generator)
6- compute mu:
   L(x) = (x - 1) / N
   mu = L(g^lambda mod N²)^(-1) mod N
7- result: public key is (N, g, N²), private key is (lambda, mu)
```

# encrypt and decrypt
encryption is probabilistic — same message encrypts differently each time because of random r
```
encrypt: c = g^m * r^N mod N²      (r is random, gcd(r, N) = 1)
decrypt: m = L(c^lambda mod N²) * mu mod N
```

# why does decryption work?
because lambda and mu are inverses of each other through the L function, similar to how e and d are inverses in RSA

# what does the attacker have?
```
- N  — the modulus (public)
- g  — the generator (public)
- c  — the encrypted message (public)
```
breaking it requires factoring N into p and q, same hard problem as RSA