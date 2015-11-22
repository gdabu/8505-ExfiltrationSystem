##################################################################################
##  SOURCE FILE:    AesEncryption.py
##
##  AUTHOR:         Geoff Dabu
##
##  PROGRAM:        Utility functions for encrypting and decrypting through AES.
##
##
##  FUNCTIONS:      encrypt(string)
##					decrypt(string)
##
##  DATE:           October 17, 2015
##
##  REVISIONS:
##
##################################################################################
from Crypto.Cipher import AES
import base64

SECRET_KEY = '12345678901234567890123456789012'

##################################################################################
##  FUNCTION
##
##  Name:           encrypt
##  Parameters:     string - plaintext which is to be encrypted
##  Return Values:  string - the ciphertext
##  Description:    encrypts plain text using AES
##################################################################################
def encrypt(plainText):
  
  secretKey = AES.new(SECRET_KEY)
  padding = (AES.block_size - len(str(plainText)) % AES.block_size) * "\0"
  plainTextWithPadding = str(plainText) + padding
  cipherText = base64.b64encode(secretKey.encrypt(plainTextWithPadding))
  
  return cipherText

##################################################################################
##  FUNCTION
##
##  Name:           decrypt
##  Parameters:     string - encrypted data
##  Return Values:  string - the decrypted plain text
##  Description:    decrypts data that has been encrypted with AES
##################################################################################
def decrypt(encryptedData):
  
  secretKey = AES.new(SECRET_KEY)
  plainTextWithPadding = secretKey.decrypt(base64.b64decode(encryptedData))
  plainText = plainTextWithPadding.rstrip("\0")
  
  return plainText
