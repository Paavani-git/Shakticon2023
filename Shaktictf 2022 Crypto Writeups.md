# Shaktictf 2022 Crypto Writeups

### Challenge Title: Eazy_peaZy
### Challenge Description :
Who knew encryption could be so simple?



### Difficulty Level
Beginner

### Points
50
 
### Flag format 
shaktictf{...}

### Author
Rees

### Writeup
This is the combination of base64 and shifting

```python!
from base64 import b64decode

x = 'ZFlSXGVaVGVXbFRjamFlIVAiZFBkZmEkY1BWUmtqampqampQWFQlJCNlYyYnWCVlYyYlbg=='

x = b64decode(x)
flag = ''
for i in x:
    flag = flag + chr(i +15)

```
#### flag 
`shaktictf{crypt0_1s_sup3r_eazyyyyyy_gc432tr56g4tr54}`

## Challenge Title: secRetS And seCReTs

### Challenge Description :
I think Sun Tzu forgot that greater the number of primes used, stronger would be the encryption.

### Author
Rees

### Difficulty Level
Easy

### Points
100

### Flag format 
shaktictf{...}

### Writeup
The challenge uses crt and rsa to encrypt the flag. From the final assert statement provided in the source code it can be seen that the secret (which is given) when divided by an unknown value x, would give us the modulus that we require to perfrom RSA decryption.

From the first assert statement we can infer that x can be retrieved by performing the chinese remainder theorem on the array n and c given using the crt function in the sympy module.
from sympy.ntheory.modular import crt
x=crt(n,c)[0]
```
#x=175393906935410597646312735251121734825355066308014883020996453700680562811773639892091486800372429659125492317788178170078374593410001133290406346042424977949257610021473876645919378922293673885436422442069899845701280009009220968827934275876545186933778202134359447023530167415550308017091921680916413562203
```
Once x is retrieved, N can be found as secret//x
N=secret//x

```
#N=24527876714777610556168704102334063247745307067942987179946992203143782911214218738693269763284353107444558551004104842495208613554362680493609315262323088218069305109094883023250460622553819850578030167910933028392613333549556209547555445147475324578694902644739395420556980677634640744378713609298141891560253460328397733071122264628468706243972435551492706426936176969047044900758569383152320313902601091822535952698142154712130550473808314533625099780507036524949344974327532792045713711551245809959038345909568860198589805752319051021759477458800632328558389734253607892450861044270982742648526813361769154927281
```

From the hint we can understand the number of primes used to set our private key was less. So, on using sympy's factorint function we can see that n factorises into a squared prime.
```python
from sympy import factorint
factorint(N)
```
```
#{156613782007770984536049055700840395037085682399926189984796410929143868636172989598027406051641994725886674336805075334390044528511942285958708618671006005927130990180083143883853840126990685118290412751594654157367930730824790742241421921147161987915110899307344903473712967071752529319870067482601269289159: 2}

#p=156613782007770984536049055700840395037085682399926189984796410929143868636172989598027406051641994725886674336805075334390044528511942285958708618671006005927130990180083143883853840126990685118290412751594654157367930730824790742241421921147161987915110899307344903473712967071752529319870067482601269289159
```

We can now calculate Euler's totient as p*(p-1) as N=p^2
```python
phi=p*(p-1)
```
```
#phi=24527876714777610556168704102334063247745307067942987179946992203143782911214218738693269763284353107444558551004104842495208613554362680493609315262323088218069305109094883023250460622553819850578030167910933028392613333549556209547555445147475324578694902644739395420556980677634640744378713609298141891560096846546389962086586215572767865848935349869092780236951380558117901032122396393554292907850959097096649278361337079377740505945296372247666391161836030519022213984147449648161859871424255124840747933157974206041221875021494260279518055537653470340643278834946262988977148077199230213328656745879167885638122

```
Using the inverse function we can calculate the private key d as inverse of e and euler's totient.

```python=
from Crypto.Util.number import inverse
d=inverse(e,phi)
```
```
#d=12976716501083114741505370666039473503350367456044481659067428485582257120108192415379278003301316436431713057341125275856941395818704200997221657812999197976488350337178187574426098557544724288250790240810164958625769902713944221640331262486815263578087009771595420257518229260351036796463724872594022823840933182176525919029375831248830129737097141858965988207513545296422203983807312665421181897156053905025132679686629545955176412753730886597545459522931179123030612104190678878354458814439067976007495812844445727544246548859732219763976525316341284726507536308407339008755430600740481089868997899657725988353611
```


pt_int can then be calculated by using `(ct^d)%N`
```python!
pt_int=pow(ct,d,N)
#pt_int= mpz(1058749935816526928514932347698586539511633166445946912656393573071070805207400525111857343067141631643689341)
```

The flag can then be obtained on converting the pt_int value to bytes and decoding.
```python
from Crypto.Util.number import long_to_bytes
flag=long_to_bytes(pt_int).decode()
```
#### flag 
`shaktictf{w0w_you_kn0w_h0w_RSA_&_CRT_w0rks_!}`


## cAex0r
### Challenge Description :
I tried to develop a new generator but I am not sure how it is working. 
### Difficulty Level
Easy

### Author
[b4b7gr00t](https://twitter.com/Paavani21)

### Points
100

### Flag format 
shaktictf{...}

### Writeup

This challenge is the combination of Ceaser cipher and xor. The number of letters to be shifted is given as a random number, and the key is also a random string with lenght `3` for xor.

The idea is to use a `Known Plaintext attack`.
 You have cass function, which does Ceaser cipher encryption and ciphertext.
Use the flag format `shaktictf{`.
 Brute for the `stride` value within the range of 1 to 27.
 xor `cass(b'sha',brute value)` and `ct[:3]` to get the key. xor that key with ciphertext. check whether `shaktictf{` is in `cass(pt,brute value)`.
 
```python=
from itertools import product
from pwn import xor
ct = open("ciphertext.txt","rb").read()

def cass (text,stride):
    u_alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    l_alpha="abcdefghijklmnopqrstuvwxyz"
    enc_text = ""
    for i in text:
        if i>=65 and i<= 90:
            enc_text += u_alpha[(u_alpha.find(chr(i)) + stride)%26]
        elif i>=97 and i<= 122:
            enc_text += l_alpha[(l_alpha.find(chr(i)) + stride)%26]
        else:
            enc_text += chr(i)
    return enc_text.encode()



for i in range(1,27):
    key = xor(cass(b'sha', i),ct[:3])
    pt = xor(ct,key)
    if b'shaktictf{' in cass(pt,-i):
        print(cass(pt,-i).decode())


```


#### Flag 
`shaktictf{welCom3_t0_cRyptOo_WoRLD_77846b12bfd9b91ebce67b236aa4}`




## Challenge Title: d0uble_cbc

### Challenge Description :
My uncle has been working as a schoolteacher. One fine day, he decides to give chocolates to all his students. He brought a different types of chocolates. But two students are asking for the same kind of chocolate. All chocolates of that kind are completed except one. So, he decided to change the chocolate wrapper and give the same chocolate that he has.Can you help him to find that same chocolate wrapper?
### Difficulty Level
Medium


### Author
[b4b7gr00t](https://twitter.com/Paavani21)

### Points
200

### Flag format 
shaktictf{...}

### Writeup
1. This chall is combination of two iv detection in cbc mode and cbc mac vulnerability with non zero IV.
2. Find iv using the oracle provided and use that iv as input for cbc mac oracle.
3. iv detection can done by encrypting the `pt='\x00'*32` , decrypt `ct = b"\x00"*16+bytes.fromhex(ct)[:16]` , decrypt the result again to get iv. 

```python=
from pwn import *
from os import urandom
host,port = '65.2.136.80',31351
io = remote(host,port)

io.recvuntil(b'4.exit')
io.sendline('1')
io.recvuntil(b'format\n')
pt = '\x00'*32
io.sendline(pt.encode().hex())
io.recvline()
ct = io.recvline()
ct = ct[25:-1].decode()
# host,port = '0.0.0.0',4304
io = remote(host,port)

io.recvuntil(b'4.exit')
io.sendline('2')
io.recvuntil(b'decrypt')
io.sendline(ct)
io.recvline()
pt = io.recvline()[28:-1]
ct = b"\x00"*16+bytes.fromhex(ct)[:16]

io = remote(host,port)
io.recvuntil(b'4.exit')
io.sendline('2')
io.recvuntil(b'decrypt')
io.sendline(ct.hex())
io.recvline()
iv_dec = (bytes.fromhex(io.recvline()[28:-1].decode())[16:]).hex()
```

5. Now pass that iv to the sign function. It will return the tag as ct[16:].
```python=
io.recvuntil(b'4.exit')
io.sendline('3')
io.recvuntil(b'further')
io.sendline(iv_dec)
io.recvuntil(b'messages\n')
io.sendline('0')
io.recvline()
msg1 = urandom(16).hex()
io.recvline()
io.sendline(msg1)
io.recvline()
io.recvline()
tag1 = (io.recvline().decode())[:-1]
```
6. sign funtion is returning the last 16 bytes from `ct`. 


7. sign(sign(block0) xor block1) gives the same sign value. (So, simply append the ciphertext of the previous block)


#### Flag
`shaktictf{double_cheese_double_mac_yummyyyy_4120686170707920636263206d6f6465}`

### r33d3m_rand0m

### Challenge Description :
You know, everything is fair in CTFs and competition.

### Author
[b4b7gr00t](https://twitter.com/Paavani21)

### Difficulty Level
Hard

### Points
300

### Flag format 
shaktictf{...}

#### Writeup

This is a simple `Random faults attack` which works with RSA decryption and signature verification with CRT. A signature can be built using CRTof Sp, Sq, Sr. Sp, Sq, and Sr are signatures of hash function with p,q, and r, respectively. 

```py=
p,q,r = getPrime(256),getPrime(256),getPrime(256)
n =  p*q*r
e = 65537
phi = (p-1)*(q-1)*(r-1)
d = inverse(e,phi)
ct = pow(bytes_to_long(flag),e,n)

h =int(sha256(flag).hexdigest(),16)

dp = d%(p-1)
dq = d%(q-1)
dr = d%(r-1)

sp = pow(h,dp,p)
sq = pow(h,dq,q)
sr = pow(h,dr,r)

s = (((sp*q*r*(inverse(q*r,p)))%n) + (sq*p*r*(inverse(p*r,q)) %(n)) + ((sr*p*q*(inverse((p*q),r)))%n))%n 

```

`s` is the signature.

Now, it is easy to find p,q,r,when the attacker has the full knowledge of `h`.


If the signature is valid, i.e., `s^e mod N = h`, the attacker has a chance to manipulate `Sp, Sq and Sr` values. If you compute the signature using changed `Sp, Sq, and Sr` values, the verification fails. Now give faults Sp value, i.e., add some value to `Sp ( Sp+3 )` for first signature verification and don’t change `Sq and Sr`. Calculate `gcd(S^e - h,n)`, which is equal to the `product of q and r`. In the same way, input `Sp, modified_Sq, Sr`, and get the `product of p and r`. Next, find the `product of p and q`.


```python=
sp1 = sp+2      #create faults value one each time
sq1 = sq+2      #create faults value
sr1 = sr+2


io = remote(host,port)    
io.recvuntil(b'provided\n')
n = int(io.recvline()[4:-1])
e = int(io.recvline()[4:-1])
h = int(io.recvline()[4:-1])
io.recvuntil(b'values\n')
io.sendline('2')
io.recvuntil(b'sp value: ')
io.sendline(str(sp1))
io.recvuntil(b'sq value: ')
io.sendline(str(sq))
io.recvuntil(b'sr value: ')
io.sendline(str(sr))

qr = GCD((s**e)-h , n )
```

```python=
pr = GCD((s**e)-h , n)
pq = GCD((s**e)-h , n)

p = GCD(pq,pr)
q = GCD(pq,qr)
r = GCD(pr,qr)     
```

find `pq` and `pr` in the same way. 

Now find the `gcd(pq,pr),gcd(pq,qr) and gcd(pr,qr)` to get `p`,`q` and `r` values respectively.

```python=
phi = (p-1)*(q-1)*(r-1)
d = inverse(e,phi)
pt = long_to_bytes(pow(ct,d,n))

print(pt)

```

#### flag

`shaktictf{rand0m_cr4z7_p3rs0n_aLw4ys_tries_cr7pt0_a7de4873ca0f9f697f1d2c09004f33dc1ad98b64}`