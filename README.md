Aaron Scofield - CIS3319 - Dr. Du
A modified implementation and applicaiton of HMAC encryption. 
This was created and submitted as Lab 3 of CIS3319, Wireless Networks and Security at Temple University. 

Assignment Prompt:
It is an individualwork using socket programming. Client C and Server S share a key for HMAC
in an offline manner (e.g., a local file). Client C then generates a message, gets the HMAC digest of this message, 
and encryptsthe message along with its HMAC to obtain ciphertext. Then C sends this ciphertext to Server S. 
Server S decrypts received ciphertext and then verifies the integrity of the received message by generating another 
HMAC with the shared HMAC key and matchesthe two HMACs. Client C and Server S switch the roles and do the above again.
All the transmitted messages should be encrypted with DES.
