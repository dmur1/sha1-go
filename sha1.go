package main

import (
    "fmt"
    "encoding/binary"
)

const (
    blockSize     = 64
    outputSize    = 20
    sha1BlockSize = 512
)

func sha1PadMessage(message []byte) ([]byte) {
    messageLenghtBytes := len(message)
    messageLengthBits := messageLenghtBytes * 8

    numZeroBits := (448 - (messageLengthBits + 1)) % sha1BlockSize
    if numZeroBits < 0 {
        numZeroBits += sha1BlockSize
    }

    numBitsPadding := blockSize + 1 + numZeroBits
    numPaddingBytes := numBitsPadding / 8

    paddedMessage := make([]byte, messageLenghtBytes + numPaddingBytes)

    copy(paddedMessage, message)

    paddedMessage[messageLenghtBytes] = 0x80

    binary.BigEndian.PutUint64(
        paddedMessage[len(paddedMessage) - 8:], uint64(messageLengthBits))

    return paddedMessage
}

func sha1(message []byte) ([]byte) {
    paddedMessage := sha1PadMessage(message)

    numBlocks := len(paddedMessage) / blockSize

    H := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}

    W := make([]uint32, 80)

    for i := 0; i < numBlocks; i++ {
        block := paddedMessage[i * blockSize : (i + 1) * blockSize]

        for j := 0; j < 16; j++ {
            W[j] = binary.BigEndian.Uint32(block[j * 4: (j + 1) * 4])
        }

        for j := 16; j < 80; j++ {
            temp := W[j-16] ^ W[j-14] ^ W[j-8] ^ W[j-3]
            W[j] = (temp << 1) | (temp >> 31)
        }

        A, B, C, D, E := H[0], H[1], H[2], H[3], H[4]

        for j := 0; j < 20; j++ {
            temp := E + ((B & C) | ((^B) & D)) + ((A << 5) | (A >> 27)) + W[j] + 0x5A827999
            E, D, C, B, A = D, C, (B << 30) | (B >> 2), A, temp
        }

        for j := 0; j < 20; j++ {
            temp := E + (B ^ C ^ D) + ((A << 5) | (A >> 27)) + W[j + 20] + 0x6ED9EBA1
            E, D, C, B, A = D, C, (B << 30) | (B >> 2), A, temp
        }

        for j := 0; j < 20; j++ {
            temp := E + ((B & C) | (B & D) | (C & D)) + ((A << 5) | (A >> 27)) + W[j + 40] + 0x8F1BBCDC
            E, D, C, B, A = D, C, (B << 30) | (B >> 2), A, temp
        }

        for j := 0; j < 20; j++ {
            temp := E + (B ^ C ^ D) + ((A << 5) | (A >> 27)) + W[j + 60] + 0xCA62C1D6
            E, D, C, B, A = D, C, (B << 30) | (B >> 2), A, temp
        }

        H[0] += A
        H[1] += B
        H[2] += C
        H[3] += D
        H[4] += E
    }

    hash := make([]byte, outputSize)
    binary.BigEndian.PutUint32(hash[0:], H[0])
    binary.BigEndian.PutUint32(hash[4:], H[1])
    binary.BigEndian.PutUint32(hash[8:], H[2])
    binary.BigEndian.PutUint32(hash[12:], H[3])
    binary.BigEndian.PutUint32(hash[16:], H[4])

    return hash
}

func main() {
    hash := sha1([]byte("test"))
    fmt.Printf("%x\n", hash)
}
