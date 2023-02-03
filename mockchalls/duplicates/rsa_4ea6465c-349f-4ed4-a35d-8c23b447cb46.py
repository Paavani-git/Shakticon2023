from Crypto.Util.number import *

from unknown import flag,x,p,q

n=p*q

b=9024902201810984522874457389632691023789197473086519213024102911128364563164112704670750166522134251126954357128154509293996953355732377962746300792955418

assert n**2==b*x - x**2

e=65537

ct=(pow(bytes_to_long(flag.encode()),e,n))



with open('out.txt','w') as f:

	f.write('n='+str(n) +'\n')

	f.write('ct='+str(ct)+'\n')

	f.write('e='+str(e)+'\n')