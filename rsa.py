from Crypto.PublicKey.RSA import generate;
print(generate(512));
print(generate());

from Crypto.PublicKey import RSA;
keyGenerator = RSA.generate;
print(RSA.generate(512));
print(keyGenerator(512));

import Crypto.PublicKey.RSA as Encryptor;
print(Encryptor.generate(512));

import Crypto.PublicKey.RSA;
print(Crypto.PublicKey.RSA.generate(512));

import Crypto.PublicKey.RSA;
parameter = 1024;
print(Crypto.PublicKey.RSA.generate(parameter));

"""
import Crypto.PublicKey.RSA.generate;
print(generate(1024));
"""
