import rabinMiller, rsahelp, RSA_KeyGen


# is given ciphertext conglomerate cipherText and modulo n, and publicKey(e)
# ciphertext input is in form [message length(bits)]_[block size(bits)]_c
# publicKey is in form (n, e)
# Tries to find prime factorization of n
# For each found possible factorization, checks if decoding c w/ those primes makes sense
# If it does, record computation time, if not, keep finding more factorizations
# returns True/False(solved or not), found privateKey, computation time.
def attacker(cipherText, publicKey):
    # First, init clock

    # extract c from cipherText

    for factor in range(2, publicKey[0] // 2):  # try to systematically factor n
        if publicKey[0] % factor == 0 and rabinMiller.isPrime(factor):
        # if n is divisible by the factor
        # check if the factor is prime
        # find all possible RSA-key/sets using this factorization
            phi = (factor - 1) * ((publicKey[0] // factor) - 1)

            for possible in range(0, phi):
                # if possible is relatively prime wrt phi, see if its the publicKey
                if relativelyPrime(possible, phi):

                    otherKey = rsahelp.findModInverse(possible, phi)
                    if (otherKey != None):
                        # also should decrypt message, compare against possible messages
                        if (possible == publicKey[1]):
                            return otherKey
                        if otherKey == publicKey[1]:
                            return possible

    return None


def main():
    publicKey, privateKey = RSA_KeyGen.generateKey(5)

    testKey = (323, 31)
    foundd = attacker("teststring", publicKey)
    print('Attacker returned private Key %d, used privateKey was %d' % (foundd, privateKey[1]))

    return


# returns True if small is relatively prime to big
# else returns false
def relativelyPrime(small, big):
    if rsahelp.gcd(small, big) == 1:
        return True
    else:
        return False


if __name__ == '__main__':
    main()
