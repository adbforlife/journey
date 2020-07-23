---
title: "Crypto | Nookcrypt | UIUCTF 2020"
date: 2020-07-22T21:05:56-04:00
draft: false
---

This is a sourceless Elliptic Curve Crypto (ECC) challenge. ECC is scaryyyy, but I might as well give it a try.


## Problem
Tom Nook is testing a new encryption scheme for nookphones, but it seems to be a bit faulty... can you break it?


## Solution
We were given some service running at `nc chal.uiuc.tf 2006` so let's check it out:

```
========================================
Welcome to NookCrypt! Here we use fancy
elliptic curve encryption to keep your 
messages safe! Try it out!
========================================
1. get (encrypted) flag
2. encrypt message
3. quit
========================================

Option: 1
enc(FLAG) = (0xf31ce7cb1f2c6e7107318d76bdda50c5, 0x02d979fc3122bbaffcc1111953bc184f)
enc('hello world') = (0x4cf5afcc9bc1db0118172129b713d86a, 0xe41d8761370768aa9694b164c843dde9)

========================================
Welcome to NookCrypt! Here we use fancy
elliptic curve encryption to keep your 
messages safe! Try it out!
========================================
1. get (encrypted) flag
2. encrypt message
3. quit
========================================

Option: 2
msg: ADB
enc(0x414442) = (0x484e1ce780af07d6e50e1e6347f767df, 0x62e9d4d97fd4b2e3168cc0b5d1ef1cd0)
```

Oh man, I don't exactly know how ECC encryption works. Finally time to read more about it.. How else am I gonna solve a sourceless crypto? For anyone also trying to learn the basics, I recommend [RFC 6090](https://tools.ietf.org/html/rfc6090).

With basic knowledge of ECC, we could try to obtain as much information about the parameters used as possible. 


