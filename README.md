# X3DH_AES 
Good day! After a couple of weeks, a solution was found that allowed the implementation of the 
X3DH algorithm. The final function takes many values in addition to the main keys of the X3DH 
algorithm, specifically the OPK index, the signing key, and the signed key. Previously, there 
was an issue with signing the key, but it was resolved by adding another key that serves solely 
for client authentication. Speaking of the key index, it is chosen by the client on the other 
side, and the offline client will be informed about the selection. The AES algorithm will be 
upgraded to Double Ratchet + AES, providing a self-healing encryption method.
