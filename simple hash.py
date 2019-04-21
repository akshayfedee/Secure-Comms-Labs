#FEDEE TOYATMA, b00099349 12/02/2019
import hashlib  #IMPORT MD5 HASH LIB
myString = input('Enter Username : ')  #INPUT A STRING

myString2 = myString.swapcase()  #STRING GET CASE SWAP,IF UPPER.BECOMES LOWER. VICE VERSA
print(myString2)
s1 = hashlib.md5(myString2.encode()).hexdigest() # HASH THE SWAP STRING WITH MD5
s2 = "c89aa2ffb9edcc6604005196b5f0e0e4"  # KNOWN HASH VALUE WHERE TO STOP
print(s1)
while s1 != s2:  # WHILE S1 IS NOT EQUAL TO S2, KEEP HASHING S1 IN HASH CHAIN TILL S1 IS EQUAL TO S2
    s1 = hashlib.md5(s1.encode()).hexdigest()  #KEEP CALCULATING THE HASH
    print(s1) # OUPUT ALL THE MD5 VALUES FOR S1 TILL S2 IS FOUND
print("Hash Found!") #STOP THE LOOP AND PRINTS HASH FOUND

