---
title: "Crypto | Nookcrypt | UIUCTF 2020"
date: 2020-07-22T21:05:56-04:00
draft: false
katex: true
markup: "mmark"
---

This is a sourceless Elliptic Curve Crypto (ECC) challenge. ECC is scaryyyy, but I might as well give it a try.


## Problem
Tom Nook is testing a new encryption scheme for nookphones, but it seems to be a bit faulty... can you break it?

Hints given during ctf:
1. Cosmic rays corrupted the prime with random chance in the first option.
2. There are no faults in the second option.


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

As a short summary of notation, we have some elliptic curve group 

$$ y^2 = x^3 + ax + b $$ 

over some field $$ \mathbb{F}_p $$. Additionally, we have some [generator](https://mathworld.wolfram.com/GroupGenerators.html) point $$g$$ of one of its [cyclic subgroup](https://mathworld.wolfram.com/CyclicGroup.html). Encrypting message $$m$$ is done by $$g^m$$, and we can't derive $$m$$ just from $$g$$ and $$g^m$$ since discrete log is hard. The mathy terms here might seem confusing if you are unfamiliar with them, but it's worth it to figure out what they mean.

Armed with basic knowledge of ECC, we could try to obtain as much information about the parameters used as possible.


### Derive g
The first thing I thought of is to obtain $$g$$ by using option 2 to encrypt the integer 1, since in any group $$g^1 = g$$. Here's a script for that:

```python
from pwn import *
r = remote('chal.uiuc.tf', 2006)
def enc(n):
    r.recvuntil(b'3. quit')
    r.sendline(b'2')
    r.sendline(n.to_bytes(100, 'big'))
    s = r.recvuntil(b'Welcome')
    s = s.split(b') = ')[1]
    s = s.split(b'\n')[0]
    return eval(s)
print(enc(1))
# (164048790688614013222215505581242564928, 52787839253935625605232456597451787076)
```


### Derive p
Since we basically can get as many points on the curve as we want, it shouldn't be too difficult to figure out the prime we are modding our operations with. Here's my intuitive approach (probably not the most slick but does the job):

Let $$(x_1, y_1), (x_2, y_2), (x_3, y_3), (x_4, y_4)$$ be four points on the curve. Then we know

$$ 
\begin{cases} 
x_1^3 + ax_1 + b - y_1^2 + pk_1 = 0\\
x_2^3 + ax_2 + b - y_2^2 + pk_2 = 0\\
x_3^3 + ax_3 + b - y_3^2 + pk_3 = 0\\
x_4^3 + ax_4 + b - y_4^2 + pk_4 = 0\\
\end{cases}
$$

where $$k_1, k_2, k_3, k_4$$ are integers and we are doing additions and multiplications above not in $$\mathbb{F}_p$$ but in $$\mathbb{Z}$$ (no modding). Since the points are known to us, we can simplify to

$$
\begin{cases}
(k_1 - k_2)p - (x_1 - x_2)a = (y_1^2 - y_2^2) - (x_1^3 - x_2^3) = c_1\\
(k_3 - k_4)p - (x_3 - x_4)a = (y_3^2 - y_4^2) - (x_3^3 - x_4^3) = c_2\\ 
\end{cases}
$$

where $$c_1, c_2$$ are constants we know. Then, we can cancel out $$a$$ to get some multiple of $$p$$:

$$
((x_3-x_4)(k_1-k_2) - (x_1-x_2)(k_3-k_4))p \\
= c_1(x_3-x_4) - c_2(x_1-x_2) = d
$$

where $$d$$ is a constant we know. Ha, now we have some multiple of $$p$$ for every 4 encrypted points. Taking gcd of them gives us $$p$$ (factoring also works). There are probably a lot of other ways of getting the prime used here, which is

```
p
= 0xfffffffdffffffffffffffffffffffff 
= 340282366762482138434845932244680310783
```


### Parameters
With $$p$$, we can derive $$a$$ and $$b$$ quite easily (if you've followed the writeup to this point, this should be simple):
```
p = 340282366762482138434845932244680310783
a = 284470887156368047300405921324061011681
b = 126188322377389722996253562430093625949
g = (164048790688614013222215505581242564928, 52787839253935625605232456597451787076)
```


### Fault Attack
We got what we wanted for the curve being used. Now let's figure out why the problem says option 1 seems to be a bit **faulty**. After experimenting a little bit, we see that option 1 sometimes returns just `err` instead of the normal encrypted flag:
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
err
```

This is probably caused by the aforementioned **fault** in the prime sometimes. Just having err gives us nothing, so I wrote a script (with `from pwn import *`) to test if we get some different points as encrypted flags. I collected 200 pairs of **faulty** (encrypted flag, encrypted hello world) for further analysis (you really don't need that many to derive flag). One example would be
```
fault_flag = (0x367381f5c0d8d000fbc9f83db7224279, 0xae350396c54c3065ee8fad1dee9c4675)
fault_hello = (0x207ef8b8f05c8a560bd56ca6ece15642, 0x769bada1ee9ef60a633fa7af616c5020)
```

So the question is, what happens if we use some random number to mod with when we compute ECC encryptions (although this problem seemed too guessy without source, the hints by problem author during ctf cleared things up a lot)?

Ok, time for more reading. After looking around, this paper is basically all you need to understand the situation here: [https://eprint.iacr.org/2003/028.pdf](https://eprint.iacr.org/2003/028.pdf).

As a short summary, if we use a composite modulus for elliptic curve multiplication by a scalar, then you can treat $$q = g^\text{flag}$$ as a point on multiple elliptic curves with the prime factors as fields. Stack exchange provides a more thorough description [here](https://crypto.stackexchange.com/questions/72613/elliptic-curve-discrete-log-in-a-composite-ring). If the prime factors are small enough, then we can just derive the discrete log for

$$ q = g^\text{flag} $$

where g has some small [order](https://mathworld.wolfram.com/GroupOrder.html) r on some elliptic curve. This essentially gives us flag mod $$r$$. If we collect enough of these, we could use Chinese Remainder Theorem (CRT) to solve for flag! Now that we've got a plan, let's execute it with sage.


### Derive modulus
At this point, if you are confused about how faulty points or faulty primes still allow encryption to go through, or about how we have points end up in some other elliptic curve, it might be helpful to reread the linked paper. It certainly made it clearer for me. The tl;dr for that is that elliptic curve point addition and scalar multiplication do not use the $$b$$ parameter so calculations happen as if they were on a different elliptic curve with a different $$b$$.

For each pair of faulty flag and hello world, we know of a total of three points on the new curve. We could then use $$gcd$$ to derive it:
```python
def derive_modulus(fault_flag, fault_hello):
    c1 = g[1]^2 - g[0]^3 - a * g[0]
    c2 = fault_flag[1]^2 - fault_flag[0]^3 - a * fault_flag[0]
    c3 = fault_hello[1]^2 - fault_hello[0]^3 - a * fault_hello[0]
    modulus = gcd(c1-c2, c2-c3)
    if abs(modulus - p) >= 0xffffffff:
        return None
    return modulus
```

After experimentation, we know that the new modulus only changes the last 32 bits of the original prime $$p$$, so we could just ignore derived moduli that don't give us something close to $$p$$.


### Derive orders and mods
For each new modulus, if it has a small prime factor, we want to derive $$f$$ and $$r$$ such that

$$ flag \equiv f \mod r $$

where $$g^\text{flag} = \text{fault\_flag}$$ on new curve and $$r$$ is the order of $$g$$. We can derive these as follows:
```python
def derive_om(modulus, fault_flag, fault_hello):
    # New b for new curve
    bf = (fault_flag[1]^2 - fault_flag[0]^3 - a * fault_flag[0]) % modulus
    # New curve
    Ef = EllipticCurve(Zmod(modulus), [a, bf])
    try:
        pt = int_hello * Ef(g)
        assert(pt == Ef(fault_hello))
    except:
        return None

    # Factor modulus
    factors = list(map(lambda x: x[0], list(factor(modulus))))
    # Let's just use the small prime factors
    factors = list(filter(lambda x: x <= 0xffffffffff, factors))
    # For each curve on small prime field, find the new b parameters
    bs = [solve_b(factor, g) for factor in factors]
    # New curves on prime fields
    Es = [EllipticCurve(GF(factors[i]), [a, bs[i]]) for i in range(len(bs))]
    # Orders of g
    orders = [Es[i](g).order() for i in range(len(bs))]
    # Solve discrete log cuz we CAN (also cuz sage is too powerful)
    mods = [discrete_log(Es[i](fault_flag), Es[i](g), orders[i], operation='+') for i in range(len(bs))]
    return orders, mods
```

### Get flag
We could get as many faulty encrypted flags as we wanted so I just used the first fifty I saw to get some CRT equations. To solve CRT, we have a short script here:
```python
def crt(orders, mods):
    M = prod(orders)
    Ms = [M // orders[i] for i in range(len(orders))]
    parts = [Ms[i] * int(pow(Ms[i], -1, orders[i])) * mods[i] for i in range(len(orders))]
    return sum(parts) % M
```
This gives us flag
```
uiuctf{th4t_5ur3_w4s_f4ulty_huh?}
```

For anyone interested, overall script is [solve.sage](/uiuctf20/solve.sage).

### Comments
1. I did not end up solving this challenge during the CTF since I only read about the fault attacks about 10 minutes before the competition ended.. I did solve it the next day though!
2. For anyone having trouble with running sage locally (it broke for me for whatever reason), you could try their docker and jupyter notebook:
```docker run -p8888:8888 sagemath/sagemath:latest sage-jupyter```
