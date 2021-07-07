s_box = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
inv_sbox = [s_box.index(x) for x in range(len(s_box))]
p_box = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38,
         54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13,
         29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
inv_p_box = [p_box.index(x) for x in range(64)]
rounds = 32


# sbox layer taking hexadecimal string block
def sBoxLayer(state):
    sub_block = ""
    for i in range(len(state)):
        sub_block += str(hex(s_box[int(state[i], 16)])[2])
    return int(sub_block, 16)


def sBoxLayerInverse(state):
    sub_block = ""
    for i in range(len(state)):
        sub_block += str(hex(inv_sbox[int(state[i], 16)])[2])
    return int(sub_block, 16)


def sBox4Layer(state):
    sub_block = ""
    state = hex(int(state, 2))
    sub_block += str(hex(s_box[int(state, 16)])[2])
    sub_block = int(sub_block, 16)
    x = '{0:04b}'.format(sub_block)
    return x


# pbox layer taking binary string block
def pLayer(state):
    perm_block = state
    perm_list = [0 for x in range(64)]  # put 64 zeros in perm_list
    for i in range(len(state)):
        perm_list[p_box[i]] = state[i]
    perm_block = ''.join(perm_list)
    return int(perm_block, 2)


def pLayerInverse(state):
    perm_block = state
    perm_list = [0 for x in range(64)]
    for i in range(len(state)):
        perm_list[inv_p_box[i]] = state[i]
    perm_block = ''.join(perm_list)
    return int(perm_block, 2)


def xor2strings(string, count):
    y = '{0:05b}'.format(int(string, 2) ^ count)
    return y


def generateRoundKeys(key):
    K = []  # list of 64 bit decimal keys.
    string = bin(key)[2:].zfill(80)
    K.append(int(string[:64], 2))
    for i in range(0, 31):
        string = string[61:] + string[:61]
        string = sBox4Layer(string[:4]) + string[4:]
        string = string[:60] + xor2strings(string[60:65], i + 1) + string[65:]

        # string = string[:60] +
        K.append(int(string[0:64], 2))
    return K


def addRoundKey(state, K64):
    x = state ^ K64
    # x = '{0:064b}'.format(x)
    return x


# Round Loop for Encryption
def encrypt(state, K):
    for i in range(rounds - 1):
        # XOR with Key
        state = addRoundKey(state, K[i])

        # SBox
        state = hex(state)[2:].zfill(16)  # change int decimal to string hex/ zfill , fills zeros until the size is 16
        state = sBoxLayer(state)

        # PBox
        state = bin(state)[2:].zfill(64)
        state = pLayer(state)
        #print('round'+ str(i+1) + '      0x' + '{0:016x}'.format(state))
    state = addRoundKey(state, K[31])
    return state


def decrypt(state, K):
    for i in range(rounds - 1):
        # XOR with Key
        state = addRoundKey(state, K[-i - 1])

        # Inverse PBox
        state = bin(state)[2:].zfill(64)
        state = pLayerInverse(state)

        # Inverse SBox
        state = hex(state)[2:].zfill(16)
        state = sBoxLayerInverse(state)

    state = addRoundKey(state, K[0])
    return state


# test case 1
plain = 0x0000000000000000
key = 0x00000000000000000000
K = generateRoundKeys(key)
cipher_text = encrypt(plain, K)
print("test case 1 expected output: 0x5579c1387b228445")
print('0x' + '{0:016x}'.format(cipher_text))
plain_text = decrypt(cipher_text, K)
print('0x' + '{0:016x}'.format(plain_text))

#test case 2
plain = 0x0000000000000000
key = 0xFFFFFFFFFFFFFFFFFFFF
K = generateRoundKeys(key)
cipher_text = encrypt(plain, K)
print("test case 2 expected output: 0xE72C46C0F5945049")
print('0x' + '{0:016x}'.format(cipher_text))
plain_text = decrypt(cipher_text, K)
print('0x' + '{0:016x}'.format(plain_text))

#test case 3
plain = 0xFFFFFFFFFFFFFFFF
key = 0x00000000000000000000
K = generateRoundKeys(key)
cipher_text = encrypt(plain, K)
print("test case 3 expected output: 0xA112FFC72F68417B")
print('0x' + '{0:016x}'.format(cipher_text))
plain_text = decrypt(cipher_text, K)
print('0x' + '{0:016x}'.format(plain_text))

#test case 4
plain = 0xFFFFFFFFFFFFFFFF
key = 0xFFFFFFFFFFFFFFFFFFFF
K = generateRoundKeys(key)
cipher_text = encrypt(plain, K)
print("test case 4 expected output: 0x3333DCD3213210D2")
print('0x' + '{0:016x}'.format(cipher_text))
plain_text = decrypt(cipher_text, K)
print('0x' + '{0:016x}'.format(plain_text))


