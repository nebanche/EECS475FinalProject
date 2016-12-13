import attacker, rabinMiller, rsahelp, RSA_KeyGen, time

# runs attacker through consecutive bitlen keys
# starts at bitlen initBitLen
# runs each bitlen n times
# appends run and time information to file.
# stops when?
def shell (initBitLen, n):
    # init file
    # Append run info

    while (True):
        for c in range (0, n):
            # gen key
            publicKey, privateKey = RSA_KeyGen.generateKey(initBitLen)

            # start timer
            timeBegin = time.process_time()

            # attack
            solveKey = attacker.attacker(n, publicKey)
            timeEnd = time.process_time()
            if (solveKey != None and solveKey == privateKey[1]):
                timeCPU = timeEnd - timeBegin

                #record Time to file
                print(initBitLen, timeCPU, privateKey[0], publicKey[1], privateKey[1])
                # record time, bitlen, and keys
            c += 1
        initBitLen += 5
    return


def main():
    initBitLen = input('Enter an inital key bitlength.')
    n = input('Enter how many keys to run at each bitlength.')
    shell (int(initBitLen), int(n))

    return

if __name__ == '__main__':
    main()