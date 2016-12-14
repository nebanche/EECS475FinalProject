import sys

DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 256

#RSA_Enc.py is inspired from examples in  “Hacking Secret Ciphers with Python” by Al Sweigart

def main():
    filename = 'encrypted_file.txt'
    # THIS IS THE MODE TO CHANGE THE PROGRAM TO ENCRYPT OR DECRYPT
    mode = 'decrypt'

    if mode == 'encrypt':

        # message to encrypt
        message = "k"
        pubKeyFilename = 'eecs475_pubkey.txt'

        print('Encrypting and writing to %s...' % (filename))
        encryptedText = encryptAndWriteToFile(filename, pubKeyFilename, message)
        print('Encrypted text:')
        print(encryptedText)

    elif mode == 'decrypt':
        privKeyFilename = 'eecs475_privkey.txt'
        print('Reading from %s and decrypting...' % (filename))
        decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)

        print('Decrypted text:')
        print(decryptedText)


def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # converts a string message to a list of block inegers. Each integer
    # represents 'blockSize' string characters.


    messageBytes = message.encode('ascii')

    blockInts = []
    # calcualtes the block integer for this block of text
    for blockStart in range(0, len(messageBytes), blockSize):

        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # coverts the list of block integers to the org message string
    # org msg length is needed to properly convert he last blockinteger

    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                asciiNumber = blockInt // (BYTE_SIZE ** i)  # // is integer division
                print('ascii number', asciiNumber)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # CONVERTS
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Decrypts a list of encrypted block ints into orginal message
    #The original message length is required to properly decrypt
    # the last block. Pass in private key to decrypt

    decryptedBlocks = []
    n, d = key

    for block in encryptedBlocks:
        # plaintext = ciphertext ^d mod n
        decryptedBlocks.append(pow(block, d, n))

    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message strin
    keySize, n, e = readKeyFile(keyFilename)

    # Check that key size is greater than block size.
    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit(
            'ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or less than the key size. Either increase the block size or use different keys.' % (
            blockSize * 8, keySize))

    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])

    encryptedContent = ','.join(encryptedBlocks)

    # write out string to output file
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)

    fo = open(messageFilename, 'w')

    fo.write(encryptedContent)
    fo.close()

    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):
    keySize, n, d = readKeyFile(keyFilename)

    fo = open(messageFilename)

    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)

    blockSize = int(blockSize)

    # check keysize is equal to or greater than blocksize

    if keySize < blockSize * 8:  # * 8 to convert bytes to bits
        sys.exit(
            'ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or less than the key size. Either increase the block size or use different keys.' % (
            blockSize * 8, keySize))

    encryptedBlocks = []

    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


if __name__ == '__main__':
    main()
