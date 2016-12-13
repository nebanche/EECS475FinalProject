import random, sys, os, rsahelp, rabinMiller


def main():
    print('Making Keys')

    # filenames and key bit size
    makeKeyFiles('eecs475', 1024)
    print('Key files are made.')


def generateKey(keySize):
    # creates public and private key pair with keys that are keySize bits in size
    #

    print('selecting prime number for p')

    # select prime number from list for p

    p = rabinMiller.generateLargePrime(keySize)
    print('p is : ', p)

    print('selecting prime number for q')

    q = rabinMiller.generateLargePrime(keySize)
    print('q is : ', q)

    n = p * q

    print('Generating e that is relatively prime to (p-1)*(q-1)')

    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** keySize)
        if rsahelp.gcd(e, (p - 1) * (q - 1)) == 1:
            break

    # Calcuates the d, the mod inverse of e

    print('Calcuating d that is mod inverse of e...')
    d = rsahelp.findModInverse(e, (p - 1) * (q - 1))

    print('d is : ', d)
    publicKey = (n, e)
    privateKey = (n, d)

    print('Public key:', publicKey)
    print('Private key:', privateKey)

    return (publicKey, privateKey)


def makeKeyFiles(name, keySize):
    # creates two files 'x_p

    if os.path.exists('%s_pubkey.txt' % (name)) or os.path.exists('%s_privkey.txt' % (name)):
        sys.exit('WARNING: The file already exists! Use a different name or delete these files' % (name, name))

    publicKey, privateKey = generateKey(keySize)

    print()
    print('The public key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing private key to file %s_privkey.txt...' % (name))
    fo = open('%s_pubkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, publicKey[0], publicKey[1]))
    fo.close()

    print()
    print('The private key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing private key to file %s_privkey.txt...' % (name))
    fo = open('%s_privkey.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, privateKey[0], privateKey[1]))
    fo.close()


if __name__ == '__main__':
    main()
