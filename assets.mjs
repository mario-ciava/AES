export const GF = function(a, b) {
    let result = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        const highBit = a & 0x80;
        a <<= 1;
        if (highBit) a ^= 0x1b;
        b >>= 1; 
    }
    return result & 0xFF;
}

export const GFInverse = function(byte) {
    if (byte === 0) return 0;
    let inv = 1, temp = byte;
    for (let i = 0; i < 254; i++) {
        temp = GF(temp, byte);
        if (temp === 1) return inv;
        inv = temp;
    }
    return inv;
}

export const affineTransform = function(byte) {
    let transformed = 0;
    for (let i = 0; i < 8; i++) {
        const bit = (byte >> i) & 1;
        const bitValue = bit ^ ((byte >> ((i + 4) % 8)) & 1) ^ ((byte >> ((i + 5) % 8)) & 1)
                         ^ ((byte >> ((i + 6) % 8)) & 1) ^ ((byte >> ((i + 7) % 8)) & 1);
        transformed |= (bitValue << i);
    }
    return transformed ^ 0x63;
};

export const genSBoxValue = function(byte) {
    const inv = GFInverse(byte);
    return affineTransform(inv).toString(16).padStart(2, '0');
};

export const sBoxReverse = [
    [ "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" ],
    [ "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" ], 
    [ "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" ],
    [ "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" ],
    [ "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" ], 
    [ "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" ], 
    [ "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" ], 
    [ "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" ], 
    [ "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" ], 
    [ "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" ], 
    [ "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" ], 
    [ "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" ], 
    [ "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" ], 
    [ "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" ], 
    [ "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" ], 
    [ "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" ] 
];

export const rCon = [ 
    [ "01", "00", "00", "00" ],
    [ "02", "00", "00", "00" ],
    [ "04", "00", "00", "00" ],
    [ "08", "00", "00", "00" ],
    [ "10", "00", "00", "00" ],
    [ "20", "00", "00", "00" ],
    [ "40", "00", "00", "00" ],
    [ "80", "00", "00", "00" ],
    [ "1b", "00", "00", "00" ],
    [ "36", "00", "00", "00" ] 
];
