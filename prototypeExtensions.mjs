Number.prototype.toHex = function() {
    return this.toString(16).padStart(2, '0');
};

String.prototype.isHex = function() {
    const cleanedStr = this.trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
    if (!cleanedStr.length) return false;

    const hexPattern = /^[0-9a-f]+$/;
    return hexPattern.test(cleanedStr);
}


String.prototype.toHex = function() {
    return Buffer.from(this, 'utf-8').toString('hex');
};

String.prototype.toText = function() {
    return Buffer.from(this, 'hex').toString('utf-8');
};

String.prototype.capitalize = function() {
        return this.charAt(0).toUpperCase() + this.slice(1);
    }

String.prototype.addPKCS7 = function(blockSize = 16) {
    const paddingLength = blockSize - (this.length / 2) % blockSize;
    const paddingValue = paddingLength.toHex().padStart(2, '0');
    const padding = paddingValue.repeat(paddingLength);
    return this + padding;
};

String.prototype.removePKCS7 = function() {
    const paddingValue = parseInt(this.slice(-2), 16);
    if (paddingValue < 1 || paddingValue > 16) {
        console.warn("Invalid padding.");
        return this
    }
    return this.slice(0, -paddingValue * 2);
};

String.prototype.applySHA256 = function (iterations = 50) {
    const ascii = this;
    const maxWord = Math.pow(2, 32);
    let result = '';

    const words = [];
    let asciiBitLength = ascii.length * 8;

    let hash = this.applySHA256.h = this.applySHA256.h || [];
    const k = this.applySHA256.k = this.applySHA256.k || [];
    let primeCounter = k.length;

    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (let i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0;
            k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
        }
    }

    for (let iter = 0; iter < iterations; iter++) {
        let asciiWithPadding = ascii + '\x80';
        while (asciiWithPadding.length % 64 - 56) asciiWithPadding += '\x00';

        for (let i = 0; i < asciiWithPadding.length; i++) {
            const j = asciiWithPadding.charCodeAt(i);
            if (j >> 8) return;
            words[i >> 2] |= j << ((3 - i) % 4) * 8;
        }

        words[words.length] = ((asciiBitLength / maxWord) | 0);
        words[words.length] = asciiBitLength;

        for (let j = 0; j < words.length;) {
            const w = words.slice(j, j += 16);
            const oldHash = hash.slice(0);

            for (let i = 0; i < 64; i++) {
                const w15 = w[i - 15], w2 = w[i - 2];
                const a = hash[0], e = hash[4];
                const temp1 = hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
                    ((e & hash[5]) ^ ((~e) & hash[6])) + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] +
                        (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) + w[i - 7] +
                        (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) | 0);
                const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
                    ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

                hash = [(temp1 + temp2) | 0].concat(hash);
                hash[4] = (hash[4] + temp1) | 0;
            }

            for (let i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            }
        }
    }

    for (let i = 0; i < 8; i++) {
        for (let j = 3; j + 1; j--) {
            const b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? '0' : '') + b.toString(16);
        }
    }

    return result;
};

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
};