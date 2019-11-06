#! /usr/bin/python3
import numpy as np
import array
from itertools import permutations
import random
import math


def _readquadgrams(quadfile):
    quadgrams = {}
    for line in open(quadfile, 'r'):
        key, count = line.split(' ')
        quadgrams[key] = int(count)
    return quadgrams


def _probquadgrams(quadcounts):
    N = sum(quadcounts.values())
    probabilities = {}
    for quad, freq in quadcounts.items():
        probabilities[quad] = math.log10(float(freq)/N)  # log probabilities
    return probabilities


def _fitness(text, quadprobs):
    L = len(text)
    smallesprob = min(quadprobs.values()) - 1
    fit_score = 0
    for i in range(L-4):
        quad = text[i:i+4]
        if quad in quadprobs:
            fit_score += quadprobs[quad]
        else:
            fit_score += smallesprob
    return fit_score


def _importciphertext():
    file_cipher = open("ciphertext.txt", "r")
    ciphertext = file_cipher.read()
    file_cipher.close()
    return ciphertext


def _createpairs(ciphertext):
    num_pairs = int(len(ciphertext)/2)
    pairs = []
    for i in range(num_pairs):
        pairs.append(ciphertext[2*i:2*(i+1)])
    return pairs


def _makegrid(key):
    grid = []
    for i in range(5):
        row = []
        for j in range(5):
            row.append(key[5*i+j])
        grid.append(row)
    grid = np.char.array(grid)
    return grid


def _decipherpair(pair, key):
    grid = _makegrid(key)
    c0 = np.where(grid == pair[0])
    c1 = np.where(grid == pair[1])
    c0 = list(zip(c0[0], c0[1]))
    c1 = list(zip(c1[0], c1[1]))

    if c0[0][0] == c1[0][0]:  # equal rows -> move left for decryption
        nc0 = (c0[0][1]-1) % 5  # new column 0
        nc1 = (c1[0][1]-1) % 5  # new column 1
        l0 = grid[c0[0][0], nc0]  # new letter 0
        l1 = grid[c1[0][0], nc1]  # new letter 1
        return l0 + l1
    elif c0[0][1] == c1[0][1]:
        nr0 = (c0[0][0]-1) % 5  # new row 0
        nr1 = (c1[0][0]-1) % 5  # new row 1
        l0 = grid[nr0, c0[0][1]]  # new letter 0
        l1 = grid[nr1, c1[0][1]]  # new letter 1
        return l0 + l1
    else:  # swap columns of letters
        l0 = grid[c0[0][0], c1[0][1]]
        l1 = grid[c1[0][0], c0[0][1]]
        return l0 + l1


def _decipher(ciphertext, key):
    pairs = _createpairs(ciphertext)
    decipher = []
    dec = ''
    for pair in pairs:
        decipher.append(_decipherpair(pair, key))
        dec = dec + _decipherpair(pair, key)
    return dec


def _getparent():
    abc = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    randomabc = np.random.permutation(list(abc))
    parent = ''
    for letter in randomabc:
        parent = parent + letter
    return parent


def _outputstate(fitness, i, key, text):
    print('best score so far: ' + str(fitness) + ', on iteration ' + str(i))
    print('Key: ' + key)
    print('plaintext: ' + text)


def _modifykey(parent):
    i = random.randrange(25)
    j = random.randrange(25)
    plist = list(parent)
    t = plist[i]
    plist[i] = plist[j]
    plist[j] = t
    newkey = ''
    for l in plist:
        newkey = newkey + l
    return newkey


def _decryptsa(ciphertext):

    # quadgram source: https://www.lexico.com/en/explore/which-letters-are-used-most
    quadcounts = _readquadgrams('quadgrams.txt')
    quadprobs = _probquadgrams(quadcounts)  # calculate quadgram probabilities

    p_key = _getparent()  # generate a random parent key
    p_decipher = _decipher(ciphertext, p_key)

    # rate fitness of deciphered text and store
    p_fit = _fitness(p_decipher, quadprobs)
    _outputstate(p_fit, 1, p_key, p_decipher)

    # find key using simulated annealing
    random.seed()
    temp = 200.0  # recommended for ciphertext of my length
    count = 10000
    step = 10
    while temp >= 0:
        while count > 0:
            c_key = _modifykey(p_key)
            c_decipher = _decipher(ciphertext, c_key)
            c_fit = _fitness(c_decipher, quadprobs)  # fitness of child key
            dF = c_fit - p_fit
            if dF > 0:  # set parent = child
                p_key = c_key
                p_fit = c_fit
                p_decipher = c_decipher
                _outputstate(p_fit, count, p_key, p_decipher)
            else:
                prob = math.exp(dF/temp)
                r = random.uniform(0, 1)
                if r < prob:  # set parent = child with probability e^(dF/T).
                    p_key = c_key
                    p_fit = c_fit
                    p_decipher = c_decipher
                    _outputstate(p_fit, count, p_key, p_decipher)
            count -= 1
        temp -= step


def main():
    ciphertext = _importciphertext()
    _decryptsa(ciphertext)


if __name__ == "__main__":
    main()
