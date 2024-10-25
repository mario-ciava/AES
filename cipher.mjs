import { rCon, sBoxReverse, GF, genSBoxValue } from './assets.mjs'
import  './prototypeExtensions.mjs'

export const AES = class {
    
    #defaultSettings
    
    static #validSettings = {
        bits: [128, 192, 256],
        mode: ['ECB', 'CBC'],
        deriveKey: [true, false],
        addSalt: [true, false],
        usePKCS7: [true, false],
        addHMAC: [true, false],
        salt: (value) => {
            if (!value) return null
            if (typeof value != 'string')
                throw new Error('Invalid salt value!')
            return value
        },
        IV: (value) => {
            if (!value) return null
            if (typeof value != 'string' || value.length != 32 || !value.isHex())
                throw new Error('Invalid IV value!')
            return value
        },
        HMAC: (value) => {
            if (!value) return null
            if (typeof value != 'string' || value.length != 64 || !value.isHex())
                throw new Error('Invalid HMAC value!')
            return value
        }
    };

    #initialize() {
        return {
            bits: 128,
            mode: 'CBC',
            deriveKey: false,
            usePKCS7: true,
            addSalt: false,
            salt: null,
            IV: '0'.repeat(32),
            addHMAC: true,
            HMAC: null
        };
    }

    #validateSettings(options = {}) {
        Object.keys(options).forEach(key => {
            if (!(key in AES.#validSettings)) {
                throw new Error(`Invalid option: ${key}`);
            }

            if (['salt', 'IV', 'HMAC'].includes(key)) {
                options[key] = AES.#validSettings[key](options[key])
            } else if (!AES.#validSettings[key].includes(options[key])) {
                throw new Error(`Invalid value for ${key}: ${options[key]}`);
            }
        });

        return true;
    }

    constructor() {
        this.#defaultSettings = this.#initialize()
    }
    
    reset() {
        this.#defaultSettings = this.#initialize()
        return this
    }

    getDefaultSettings() {
        return { ...this.#defaultSettings };
    }

    setDefaultSettings(options = {}) {
        this.#validateSettings(options);
        this.#defaultSettings = { 
            ...this.#defaultSettings,
            ...options,
        };
        return this
    }

    generateRandomBytes(length = 16) {
        const bytes = [];
        for (let i = 0; i < length; i++) {
            const randomValue = Math.floor(Math.random() * 256);
            bytes.push(randomValue.toHex());
        }
        return bytes.join('');
    }
    
    createStates(hexString, stateSize = 16, addPadding = (this.#defaultSettings ? this.#defaultSettings.usePKCS7 : true), performedOperation = null) {
        const pairs = Array.from({ length: Math.ceil(hexString.length / 2) }, (_, i) => hexString.slice(i * 2, i * 2 + 2)),
              states = Array.from({ length: Math.floor(pairs.length / stateSize) }, (_, i) => {
                    const hexBlock = pairs.slice(i * stateSize, (i + 1) * stateSize).join('');
                    return new State(hexBlock);
            });
        const remaining = pairs.length % stateSize,
        lastHexString = pairs.slice(states.length * stateSize).join('');

        if (!addPadding || performedOperation == "decryption") {
            if (remaining != 0)
                throw new Error(`Input length is not a multiple of ${stateSize * 2} bytes ${performedOperation == "decryption" ? '' : ', and padding is disabled.'}`)
            return states;
        }

        let paddedString = lastHexString.addPKCS7(stateSize)
        states.push(new State(paddedString));

        return states;
    }
    
    transformKey(hexKey, settings) {
        const { addSalt, salt, deriveKey, bits } = settings;

        settings.salt = salt ? salt : this.generateRandomBytes()
        hexKey = addSalt ? hexKey + settings.salt : hexKey

        if (hexKey.length !== bits / 4) {
            if (!deriveKey)
                throw new Error(`Invalid key size | Expected ${bits}-bit key.`);
            return hexKey.applySHA256().substring(0, bits / 4);
        }

        return deriveKey ? hexKey.applySHA256().substring(0, bits / 4) : hexKey;
    }

    expandKey(hexKey) {
        const key = Array.from({ length: hexKey.length / 2 }, (_, i) => hexKey.slice(i * 2, i * 2 + 2));
        const groupedKey = Array.from({ length: Math.ceil(key.length / 4) }, (_, i) => key.slice(i * 4, (i + 1) * 4));
        const expanded = [...groupedKey];
        const totalColumns = groupedKey.length === 4 ? 44 : groupedKey.length === 6 ? 52 : 60;

        const xorColumns = (col1, col2) => col1.map((byte, index) => (parseInt(byte, 16) ^ parseInt(col2[index], 16)).toHex());
        const applySubBytes = (column) => column.map(byte => {
            const byteValue = parseInt(byte, 16);
            return genSBoxValue(byteValue);
        });

        const applyRotWord = (column) => column.slice(1).concat(column[0]);

        for (let i = groupedKey.length; i < totalColumns; i++) {
            let temp = [...expanded[i - 1]];
            if (i % groupedKey.length === 0) {
                temp = applySubBytes(applyRotWord(temp));
                temp[0] = (parseInt(temp[0], 16) ^ parseInt(rCon[Math.floor(i / groupedKey.length) - 1][0], 16)).toHex();
            } else if (groupedKey.length === 8 && i % groupedKey.length === 4) {
                temp = applySubBytes(temp);
            }
            expanded.push(xorColumns(temp, expanded[i - groupedKey.length]));
        }
        return Array.from({ length: Math.ceil(expanded.length / 4) }, (_, i) => expanded.slice(i * 4, (i + 1) * 4));
    }

    validateEncryptionInput(plainText, plainKey, options) {
        this.#validateSettings(options);
        const settings = { ...this.#defaultSettings, ...options };

        if (settings.IV && !(settings.IV instanceof State))
            settings.IV = this.createStates(settings.IV).at(0);

        console.log(plainText)
        const hexText = plainText.isHex() ? plainText : plainText.toHex()
        const hexKey = plainKey.isHex() ? plainKey : plainKey.toHex()

        return { hexText, hexKey, settings };
    }

    encrypt(plainText, plainKey, options = {}) {
        const { hexText, hexKey, settings } = this.validateEncryptionInput(plainText, plainKey, options);
        const encryptedMessage = this.performEncryption(hexText, hexKey, settings);

        let hmac = settings.addHMAC ? new HMAC(hexKey).generate(encryptedMessage) : null;

        return {
            message: encryptedMessage,
            IV: settings.IV || null,
            salt: settings.addSalt ? settings.salt : null,
            HMAC: hmac,
            instance: this
        };
    }

    performEncryption(hexText, hexKey, settings) {
        const finalKey = this.transformKey(hexKey, settings);
        const expandedKey = this.expandKey(finalKey),
              states = this.createStates(hexText, 16, settings.usePKCS7, 'encryption')

        let previousEncryptedState = null;

        const encryptedStates = states.map((state, index) => {
            const toXOR = index > 0 ? previousEncryptedState : settings.IV;
            if (settings.mode == 'CBC')
                state.addRoundKey(toXOR);

            const encryptedState = state.applyEncryption(expandedKey);
            previousEncryptedState = [...encryptedState];
            
            return encryptedState.destroy();
        });

        if (settings.IV)
            settings.IV = settings.IV.destroy().join();

        return encryptedStates.join('');
    }

    decrypt(cipherText, plainKey, options = {}) {
        const { hexText, hexKey, settings } = this.validateDecryptionInput(cipherText, plainKey, options);

        if (settings.addHMAC && settings.HMAC) {
            const hmac = new HMAC(hexKey);
            if (!hmac.verify(cipherText, settings.HMAC)) 
                throw new Error('HMAC verification failed!');
        }

        const decryptedMessage = this.performDecryption(hexText, hexKey, settings);

        return {
            message: decryptedMessage,
            IV: settings.IV || null,
            salt: settings.addSalt ? settings.salt : null,
            HMAC: settings.HMAC || null,
            instance: this
        };
    }

    validateDecryptionInput(cipherText, plainKey, options) {
        this.#validateSettings(options);
        const settings = { ...this.#defaultSettings, ...options };

        if (settings.IV && !(settings.IV instanceof State))
            settings.IV = this.createStates(settings.IV).at(0);
        
        const hexKey = plainKey.isHex() ? plainKey : plainKey.toHex()
        const hexText = cipherText

        return { hexText, hexKey, settings};
    }

    performDecryption(hexText, hexKey, settings) {

        const finalKey = this.transformKey(hexKey, settings),
              expandedKey = this.expandKey(finalKey).reverse(),
              states = this.createStates(hexText, 16, settings.usePKCS7, 'decryption');

        let previousEncryptedState = null;
        const decryptedStates = states.map((state, index) => {
            const currentEncryptedState = JSON.parse(JSON.stringify(state));

            const decryptedState = state.applyDecryption(expandedKey);
            
            const toXOR = index > 0 ? previousEncryptedState : settings.IV;
            if (settings.mode == 'CBC') 
                decryptedState.addRoundKey(toXOR);

            previousEncryptedState = [...currentEncryptedState];

            return decryptedState.destroy();
        });

        let unpaddedString = '';
        if (settings.usePKCS7) {
            const lastStateIndex = decryptedStates.length - 1;
            let lastHexString = decryptedStates[lastStateIndex].join('');
            unpaddedString = lastHexString.removePKCS7();
            decryptedStates[lastStateIndex] = unpaddedString;
        }

        if (settings.IV)
            settings.IV = settings.IV.destroy().join();

        return decryptedStates.join('');
    }
}

class State extends Array {
    constructor(hexString) {
        super();
        const pairs = Array.from({ length: Math.ceil(hexString.length / 2) }, (_, i) => hexString.slice(i * 2, i * 2 + 2));
        for (let i = 0; i < 16; i += 4) this.push(pairs.slice(i, i + 4));
    }
        
    transpose() {
        const flipped = this.map((_, rowIndex) => this.map(col => col[rowIndex]));
        this.length = 0;
        this.push(...flipped);
        return this;
    }
        
    destroy() {
        this.splice(0, this.length, this.flat().join(''));
        return this
    }
    
    addRoundKey(key) {
        for (let row = 0; row < this.length; row++) {
            for (let col = 0; col < this[row].length; col++) {
                this[row][col] = (parseInt(this[row][col], 16) ^ parseInt(key[row][col], 16)).toHex();
            }
        }
        return this;
    }
    
    shiftRows(reverse = false) {
        const rotatedState = this.map((row, index) => {
            const rotations = ((reverse ? -index : index) % row.length + row.length) % row.length;
            return row.slice(rotations).concat(row.slice(0, rotations));
        });
        this.splice(0, this.length, ...rotatedState);
        return this;
    }
    
    subBytes(reverse = false) {
        const transposed = Array.from({ length: this[0].length }, (_, colIndex) =>
            this.map(row => {
                const byte = parseInt(row[colIndex], 16);
                const transformed = reverse ? sBoxReverse[byte >> 4][byte & 0x0F] : genSBoxValue(byte);
                return transformed
            })
        );
        this.length = 0;
        this.push(...transposed);
        return this;
    }
    
    mixColumns(reverse = false) {
        if (!reverse) {
            let newState = Array.from({ length: this[0].length }, () => new Array(this.length));
            for (let x = 0; x < this[0].length; x++) {
                const a = this.map(row => parseInt(row[x], 16));
                newState[x][0] = (GF(a[0], 2) ^ GF(a[1], 3) ^ a[2] ^ a[3]).toHex();
                newState[x][1] = (a[0] ^ GF(a[1], 2) ^ GF(a[2], 3) ^ a[3]).toHex();
                newState[x][2] = (a[0] ^ a[1] ^ GF(a[2], 2) ^ GF(a[3], 3)).toHex();
                newState[x][3] = (GF(a[0], 3) ^ a[1] ^ a[2] ^ GF(a[3], 2)).toHex();
            }
            this.forEach((row, i) => row.forEach((_, j) => this[i][j] = newState[i][j]));
        } else {
            let mixed = Array.from({ length: this.length }, () => []);
            for (let x = 0; x < this.length; x++) {
                const col = this[x].map(value => parseInt(value, 16));
                mixed[0][x] = (GF(col[0], 14) ^ GF(col[1], 11) ^ GF(col[2], 13) ^ GF(col[3], 9)).toHex();
                mixed[1][x] = (GF(col[0], 9) ^ GF(col[1], 14) ^ GF(col[2], 11) ^ GF(col[3], 13)).toHex();
                mixed[2][x] = (GF(col[0], 13) ^ GF(col[1], 9) ^ GF(col[2], 14) ^ GF(col[3], 11)).toHex();
                mixed[3][x] = (GF(col[0], 11) ^ GF(col[1], 13) ^ GF(col[2], 9) ^ GF(col[3], 14)).toHex();
            }
            this.forEach((row, i) => row.forEach((_, j) => this[i][j] = mixed[i][j]));
        }
        return this;
    }

    applyDecryption(expandedKey) {
        this.addRoundKey(expandedKey.at(0)).transpose().shiftRows(true).subBytes(true);

        for (let n = 1; n < expandedKey.length - 1; n++)
            this.addRoundKey(expandedKey.at(n)).mixColumns(true).shiftRows(true).subBytes(true);

        this.addRoundKey(expandedKey.at(-1));
        return this;
    }

    applyEncryption(expandedKey) {
        this.addRoundKey(expandedKey.at(0));

        for (let n = 1; n < expandedKey.length - 1; n++)
            this.subBytes().shiftRows().mixColumns().addRoundKey(expandedKey.at(n));

        this.subBytes().shiftRows().transpose().addRoundKey(expandedKey.at(-1));
        return this;
    }
}

class HMAC {
    constructor(key) {
        this.key = key;
        this.blockSize = 64;
    }

    formatKey() {
        if (this.key.length > this.blockSize) {
            this.key = this.key.applySHA256();
        }
        return this.key.padEnd(this.blockSize * 2, '0');
    }

    xorPads(pad) {
        return Array.from({ length: this.blockSize * 2 }, (_, i) =>
            (parseInt(this.key[i], 16) ^ pad).toString(16).padStart(2, '0')
        ).join('');
    }

    generate(message) {
        const oPad = this.xorPads(0x5c);
        const iPad = this.xorPads(0x36);
        
        const innerHash = (iPad + message).applySHA256();
        return (oPad + innerHash).applySHA256();
    }

    verify(message, hmac) {
        const calculatedHMAC = this.generate(message);
        return calculatedHMAC === hmac;
    }
}
