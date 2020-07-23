---
title: "Crypto | Et Tu Blathers | UIUCTF 2020"
date: 2020-07-21T22:31:04-04:00
draft: false
---

This is my first ctf writeup. How *exciting*! This problem is a warmup crypto question on Vigenere cipher.


## Problem
Et tu Mr. Mayor?! Mr mayor is eating his salad and he has a good 'Vigenerete' dressing. He is also trying to read his email, but something is wrong with the first line of this file... I think it is encoded! Can you decrypt it?

Wrap your result in uiuctf{}

You may find a wordlist of commonly used words helpful for this challenge

To clarify The first line is Ciphertext, the other lines are not.

[crypto-warmup](/uiuctf20/crypto-warmup)


## Solution
The problem description 'Vigenerete' dressing hints at the use of [Vigenere](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) cipher. In short, this is a cipher where A + A = A and ADB + BDA = BGB, calculated mod 26 using the English alphabet.

Now we have a basic idea about the hints, let's look at the unknown 1006-line text file:

```
HVTRQYPZACMZQOXMGFBDHIXANICCIN
XRFXVMKIUQHXNOLVBRKJBSYPJJOGWW
QNRQHKODVKQYLCBKLORVOBYCDBGBEF
SXZDJVYIAXZIEXCUIICKFSVGIJSAWR
KJYOENPAEOQPTGRYCHNMRLMMGMMGKY
QOQPLFQENMEOBVJFEZNMAOFFZPERUG
...
```

Woah, I have no idea what this is saying. In general, when there's unknown ciphertext, we throw it in some [frequency analysis](https://www.dcode.fr/frequency-analysis) just to get some clues. Nope. Frequency of each character is about the same.

Okay, let's look at the rest of the hints. Taking first line as ciphertext in a vigenere cipher, we just need a key to calculate the message. At this point, we might as well just try each line as key and see if the result is English.

```python
alph = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
def minus(a, b):
    res = [(alph.index(a[k]) - alph.index(b[k])) % 26 for k in range(len(a))]
    res = list(map(lambda x: alph[x], res))
    return bytes(res)

lines = open('crypto-warmup', 'rb').read().rstrip().split(b'\n')
possibles = [minus(lines[0], l) for l in lines[1:]]
[print(p) for p in possibles[:20]]
```

This gives:

```
KEOUVMFRGMFCDAMRFORUGQZLEZOWMR
RICBJOBWFSWBFMWCVRKITHZYKHWBEI
PYUOHDRRAFNRMRVSYXZTCQCUFZKCMW
XMVDMLAZWOWKXIGOEYORQXLOHWQWYP
RHDCFTZVNQILPTOHCGORHUSVOTYLOH
FGKTOEWHUETMIRHMPWSWTJCWDCLZVM
...
```

We still need to find which line looks at English the most. To do this, we assign each line a frequency score and rank them. For our purposes here, it's enough to assign each English letter a score of its [letter frequency](https://en.wikipedia.org/wiki/Letter_frequency) proportion and sum the letter scores for each line. The top results are here:

```
(1.38037, b'UEDEHYNYOHJKAAEITCOMNLIIJNFNGH')
(1.3693, b'TWVMEODORHSTSBDYWCBDLCANIEEOWS')
(1.36799, b'HMEVACIFTRORSCVXCDNOTENEOMDAJW')
(1.36127, b'TNKRLSTWRRFTEDWZNBBSDKREIVOELA')
(1.33832, b'EEHHIDHETLSIGDQIJWZEOPIDFLZSTQ')
(1.33214, b'AITHPEKYKHCWSZYEFTSTQNENXIROBT')
(1.33066, b'WYEICVDMPNEERDAEQPKBYNJASENGFE')
(1.31041, b'HSCNBANMOTPOFEFWFUPIEHIITIYAKF')
(1.29099, b'OHHECKFRICKICANTSTOPTYPINGLOUD')
(1.28721, b'SQRKNETKNNHATLLLPDSGTEQSDVZAPT')
...
```

We have our flag here:
```
uiuctf{OHHECKFRICKICANTSTOPTYPINGLOUD}
```

[exploit.py](/uiuctf20/exploit.py)


## Comments
I don't think the hint of using wordlist of commonly used words was any helpful for me. Even the random texts had some common words that would be false positives.
