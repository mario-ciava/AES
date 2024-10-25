const assets = require("./assets.js");
class AES {
    constructor(type = 128) {
        this.type = type;
 
        if (this.type != 128 && this.type != 192 && this.type != 256) {
            throw new Error("Invalid AES bit type");
        }    
 
        if (this.type == 192 || this.type == 256) {
            throw "192 BIT AND 256 BIT ENCRYPTIONS ARE NOT SUPPORTED YET!";
        }
 
        this.rounds = {
            128: 10,
            192: 12,
            256: 14
        };
 
        this.text = null;
        this.key = null;
    }
 
    textToHex(text, skip) {
        if (this.type/8 != text.length && !skip) throw new Error(`Invalid length | Must be ${this.type/8}`);
        const hex = [];
        for (var i = 0; i < text.length; i++) {
            hex.push("00".substr(text.charCodeAt(i).toString(16).length) + text.charCodeAt(i).toString(16));
        }
        return hex;
    }
 
    hexToText(hex) {
        const text = [];
        for (var i = 0; i < hex.length; i++) {
            text.push(String.fromCharCode(parseInt(hex[i], 16)));
        }
        return text.join("");
    }
 
    hexToBin(hex) {
        if (!(hex instanceof Array)) throw new Error("Invalid input type | Must be array");
        const bin = [];
        for (var i = 0; i < hex.length; i++) {
          var binary = parseInt(hex[i], 16).toString(2);
          binary = "00000000".substr(binary.length) + binary;
          bin.push(binary);
        }
        return bin;
      }
 
    pad(text, x, padding = " 00") {
        var toPad = x - text.length;
            for (var i = 0; i < toPad; i++) {
                text += padding;
            }
        return text;
    }
   
    createBlock(input, pieces = 4) {
        var block = [], values = [];
        for (var i = 0; i < input.length + 1; i++) {
            if (values.length < pieces) {
                values.push(input[i]);
            } else {
                block.push(values);
                values = [];
                values.push(input[i])
            }
        }
        return block;
    }
 
    flipBlock(block) {
        var flipped = [];
        for (var i = 0; i < block.length; i++) {
            flipped.push(new Array());
        }
        for (var x = 0; x < block.length; x++) {
            for (var y = 0; y < block.length; y++) {
                flipped[x][y] = block[y][x];
                flipped[y][x] = block[x][y];
            }
        }
        return flipped;
    }
 
    destroyBlock(block) {
        var destroyed = [];
        for (var x = 0; x < block.length; x++) {
          for (var y = 0; y < block.length; y++) {
            destroyed.push(block[x][y]);
          }
        }
        return destroyed;
      }
 
    expandKey(key, iterator) {
        var expanded = [];
   
        var lastColumn = key[key.length - 1];
        var firstColumn = key[0];
        var otherColumns = key.slice(1);
   
        const changeLastColumn = (lastColumn) => {
            lastColumn = this.shiftRows(lastColumn, 1);
                for (var x = 0; x < lastColumn.length; x++) {
                    var Index_X = assets.valueOrder.findIndex((k) => {
                        return k === lastColumn[x].split("")[0];
                    });
                    var Index_Y = assets.valueOrder.findIndex((k) => {
                        return k === lastColumn[x].split("")[1];
                    });
                    lastColumn[x] = assets.sBox[Index_X][Index_Y];
                }
            return lastColumn;
        }
   
        lastColumn = changeLastColumn(lastColumn);
   
        const expandFirstColumn = (firstColumn) => {
            for (var x = 0; x < firstColumn.length; x++) {
                let V = "0x" + firstColumn[x];
                let L = "0x" + lastColumn[x];
                let R = "0x" + assets.rCon[iterator - 1][x];
                firstColumn[x] = "00".substr((V ^ L ^ R).toString(16).length) + (V ^ L ^ R).toString(16);
            }
            return firstColumn;
        }
       
        firstColumn = expandFirstColumn(firstColumn);
   
        for (var x = 0; x < key.length; x++) {
            expanded.push(new Array());
            expanded[x].push(firstColumn[x]);
        }
       
        const expandColumn = (column, y) => {
            var expansion = [];
            for (var x = 0; x < column.length; x++) {
                let V = "0x" + column[x];
                let C = "0x" + expanded[x][y];
                expanded[x].push("00".substr((V ^ C).toString(16).length) + (V ^ C).toString(16));
                expansion.push("00".substr((V ^ C).toString(16).length) + (V ^ C).toString(16));
            }
            return expansion;
        }
   
        for (var i = 0; i < otherColumns.length; i++) {
            expandColumn(otherColumns[i], i);
        }
   
        return expanded;
    }
 
    addRoundKey(state, key) {
        state = this.flipBlock(state);
        key = this.flipBlock(key);
        for (var x = 0; x < state.length; x++) {
            for (var y = 0; y < state.length; y++) {
                let V = "0x" + state[x][y];
                let C = "0x" + key[x][y];
                state[x][y] = "00".substr((V ^ C).toString(16).length) + (V ^ C).toString(16);
            }
        }
        state = this.flipBlock(state);
        key = this.flipBlock(key);
        return state;
    }
 
    subBytes(state) {
        var newState = []
        for (var x = 0; x < state.length; x++) {
            for (var y = 0; y < state[x].length; y++) {
                var Index_X = assets.valueOrder.findIndex((k) => {
                    return k === state[x][y].split("")[0];
                });
                var Index_Y = assets.valueOrder.findIndex((k) => {
                    return k === state[x][y].split("")[1];
                });
                newState.push(assets.sBox[Index_X][Index_Y]);
            }
        }
        return this.createBlock(newState);
    }
 
    shiftRows(row, rotations) {
        return row.slice(rotations, row.length).concat(row.slice(0, rotations));
    }
 
    mixColumns(state) {
        for (var x = 0; x < state.length; x++) {
          var a = [], b = [];
          for (var y = 0; y < state[x].length; y++) {
            a.push("0x" + state[y][x]);
            b.push(a[y]&0x80 ? a[y]<<1 ^ 0x011b : a[y]<<1);
          }
          const M1 = (a[1] ^ a[2] ^ a[3] ^ b[0] ^ b[1]).toString(16),
          M2 = (a[0] ^ a[2] ^ a[3] ^ b[1] ^ b[2]).toString(16),
          M3 = (a[0] ^ a[1] ^ a[3] ^ b[2] ^ b[3]).toString(16),
          M4 = (a[0] ^ a[1] ^ a[2] ^ b[0] ^ b[3]).toString(16);
          state[0][x] = "00".substr(M1.length) + M1;
          state[1][x] = "00".substr(M2.length) + M2;
          state[2][x] = "00".substr(M3.length) + M3;
          state[3][x] = "00".substr(M4.length) + M4;
        }
        return state;
    }
 
    encrypt(text, key = null) {
        if (!text) throw new Error("Text not provided!");
        if (text.length > this.type/8) throw new Error(`Invalid text length | Must be ${this.type/8}`);
        this.text = this.createBlock(text.split(""), this.type/8);
        for (var i = 0; i < this.text.length; i++) {
            this.text[i] = this.textToHex(this.text[i].join(""), true);
            if (this.text[i].length < this.type/8) {
                this.text[i] = this.pad(this.text[i], this.type/8).split(" ");
            }
        }
        this.text = this.text[0];
 
        if (!key) throw new Error("Key not provided!");
        this.cipherkey = this.textToHex(key);
 
        const RunEncryptionFlow = () => {
           
            if (this.text.length != this.type/8) throw new Error(`Invalid text length | Must be ${this.type/8}`);
            if (this.cipherkey.length != this.type/8) throw new Error(`Invalid key length | Must be ${this.type/8}`);
 
            this.state = this.createBlock(this.text);
            this.cipherkey = this.createBlock(this.cipherkey);
           
            this.state = this.addRoundKey(this.state, this.cipherkey);
           
            for (var n = 1; n < this.rounds[this.type]; n++) {
 
                this.cipherkey = this.expandKey(this.cipherkey, n);
                this.cipherkey = this.flipBlock(this.cipherkey);
 
                this.state = this.subBytes(this.state);          
 
                this.state = this.flipBlock(this.state);
                for (var i = 0; i < this.state.length; i++) {
                    this.state[i] = this.shiftRows(this.state[i], i);
                }
               
                this.state = this.mixColumns(this.state);
                this.state = this.flipBlock(this.state);          
                this.state = this.addRoundKey(this.state, this.cipherkey);
               
            }
 
            this.cipherkey = this.expandKey(this.cipherkey, this.rounds[this.type]);
            this.cipherkey = this.flipBlock(this.cipherkey);
 
            this.state = this.subBytes(this.state);
            this.state = this.flipBlock(this.state);
            for (var i = 0; i < this.state.length; i++) {
                this.state[i] = this.shiftRows(this.state[i], i);
            }
            this.state = this.flipBlock(this.state);
            this.state = this.addRoundKey(this.state, this.cipherkey);
 
            this.output = this.destroyBlock(this.state).join("")
           
            this.state = [];
            this.cipherkey = this.textToHex(key);
            return this.output;
        }
 
        this.encrypted = RunEncryptionFlow();
        return this.encrypted;
    }
 
    inverseSubBytes(state) {
        var newState = []
        for (var x = 0; x < state.length; x++) {
            for (var y = 0; y < state[x].length; y++) {
                var Index_X = assets.valueOrder.findIndex((k) => {
                    return k === state[x][y].split("")[0];
                });
                var Index_Y = assets.valueOrder.findIndex((k) => {
                    return k === state[x][y].split("")[1];
                });
                newState.push(assets.sBoxReverse[Index_X][Index_Y]);
            }
        }
        return this.createBlock(newState);
    }
 
    inverseShiftRows(row, rotations) {
        return row.slice(rotations, row.length).concat(row.slice(0, rotations));
    }
 
    inverseMixColumns(state) {
        const m = assets.MULS, mixed = [], st = state;
        for (var i = 0; i < state.length; i++) {
            mixed.push(new Array());
        }
        for (var x = 0; x < state.length; x++) {
            const M1 = (m[14][parseInt("0x"+st[x][0])]^m[11][parseInt("0x"+st[x][1])]^m[13][parseInt("0x"+st[x][2])]^m[9][parseInt("0x"+st[x][3])]).toString(16),
                M2 = (m[14][parseInt("0x"+st[x][1])]^m[11][parseInt("0x"+st[x][2])]^m[13][parseInt("0x"+st[x][3])]^m[9][parseInt("0x"+st[x][0])]).toString(16),
                M3 = (m[13][parseInt("0x"+st[x][0])]^m[14][parseInt("0x"+st[x][2])]^m[11][parseInt("0x"+st[x][3])]^m[9][parseInt("0x"+st[x][1])]).toString(16),
                M4 = (m[11][parseInt("0x"+st[x][0])]^m[13][parseInt("0x"+st[x][1])]^m[14][parseInt("0x"+st[x][3])]^m[9][parseInt("0x"+st[x][2])]).toString(16);  
            mixed[0][x] = "00".substr(M1.length) + M1;
            mixed[1][x] = "00".substr(M2.length) + M2;
            mixed[2][x] = "00".substr(M3.length) + M3;
            mixed[3][x] = "00".substr(M4.length) + M4;
        }
        return mixed;
    }
 
    decrypt(input, key = null) {
 
        if (!input) throw new Error("Input not provided");
        if (input.length > this.type/4) throw new Error(`Invalid input length/format | Must be ${this.type/8}/hexadecimal`);
       
        input = input.toLowerCase();
        this.input = input;
 
        this.temp = [];
        this.createBlock(this.input, 2).forEach((value) => {
            return this.temp.push(value.join(""));
        });
        this.input = this.temp;
 
        this.temp = this.textToHex(key);
        this.cipherkey = this.temp;
 
        const RunDecryptionFlow = () => {
            if (this.cipherkey.length != this.type/8) throw new Error(`Invalid key length | Must be ${this.type/8}`);
            this.state = this.createBlock(this.input);
            this.cipherkey = this.createBlock(this.cipherkey);
 
            this.roundkeys = [];
            for (var i = 1; i < this.rounds[this.type] + 1; i++) {
                this.roundkeys.push(this.expandKey(this.cipherkey, i));
                this.cipherkey = this.flipBlock(this.roundkeys[i - 1]);
            }
 
            this.state = this.addRoundKey(this.state, this.flipBlock(this.roundkeys[this.roundkeys.length - 1]));
           
            this.state = this.flipBlock(this.state);
            for (var i = 0; i < this.state.length; i++) {
                this.state[i] = this.shiftRows(this.state[i], -i);
            }
            this.state = this.inverseSubBytes(this.state);
           
            this.state = this.flipBlock(this.state);
            for (var i = 1; i < this.rounds[this.type]; i++) {
                
                this.state = this.addRoundKey(this.state, this.flipBlock(this.roundkeys[this.roundkeys.length - (i + 1)]));
                this.state = this.inverseMixColumns(this.state);

                for (var x = 0; x < this.state.length; x++) {
                    this.state[x] = this.inverseShiftRows(this.state[x], -(x));
                }

                this.state = this.inverseSubBytes(this.state);
                this.state = this.flipBlock(this.state);
            }
 
            this.temp = this.createBlock(this.temp);
            this.state = this.addRoundKey(this.state, this.temp);
 
            for (x = 0; x < this.state.length; x++) {
                this.state[x] = this.hexToText(this.state[x]);
            }
           
            this.output = this.destroyBlock(this.state).join("");
 
            this.state = [];
            this.roundkeys = [];
            this.temp = this.textToHex(key);
            this.cipherkey = this.temp;    
           
            return this.output;      
        }
 
        this.decrypted = RunDecryptionFlow();
       
        this.decrypted = {
            "text": this.decrypted,
            "hex": this.textToHex(this.decrypted).join("")
        }
        return this.decrypted.text;
    }
}
 
try {
 
    //ENCRYPTION
    new AES(128).encrypt("testodi:2prova-1", "esempiodi_chiave");
    //8570482e98146f160ef8733b3f4fe715 (HEX FORMAT)
   
    //DECRYPTION
    new AES(128).decrypt("8570482e98146f160ef8733b3f4fe715", "esempiodi_chiave");
    //testodi:2prova-1 (TEXT FORMAT)
    //746573746f64693a3270726f76612d31 (HEX FORMAT)
 
} catch (error) {
    console.log(error);
}
 
//LAST EDITED: [06/19/2018 - 21:36]


