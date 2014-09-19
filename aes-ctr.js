(function() {
    'use strict';

    function genKeyStream(key, counter, length, offset) {
        var totalLength = length + offset;
        var numBlocks = Math.ceil(totalLength / 16);
        var ciphertext = new Uint8Array(numBlocks * 16);
        var i, j;

        // use counters as ciphertexts
        ciphertext.set(counter);
        var idx;
        for (i = 1; i < numBlocks; i++) {
            for (j = 0; j < 16; j++) {
                ciphertext[16 * i + j] = ciphertext[16 * (i - 1) + j];
            }
            for (j = 15; j > -1; j--) {
                idx = 16 * i + j;
                ciphertext[idx] += 1;
                if (ciphertext[idx] !== 0) {
                    break;
                }
            }
        }

        // update counter
        for (i = 0; i < 16; i++) {
            counter[i] = ciphertext[(numBlocks - 1) * 16 + i];
        }

        return crypto.subtle.decrypt(
            {
                name: 'aes-cbc',
                iv: new Uint8Array(16)
            },
            key,
            ciphertext
        ).then(
            function(plaintext) {
                plaintext = new Uint8Array(plaintext);

                // XOR counters with plaintexts to get the AES-CTR key stream we want
                var i;
                for (i = 0; i < (numBlocks - 1) * 16; i++) {
                    plaintext[16 + i] ^= ciphertext[i];
                }

                return new Uint8Array(plaintext.buffer, offset, length);
            },
            console.error.bind(console, 'decrypt error')
        );
    }


    var AesCtr = function() {};

    AesCtr.prototype.init = function(keyData, initCounter) {
        var self = this;
        self.counter = initCounter;
        self.offset = 0;

        return crypto.subtle.importKey(
            'raw', keyData,
            {
                name: 'aes-cbc',
                iv: new Uint8Array(16)
            },
            false, ['decrypt']
        ).then(
            function(key) {
                self.key = key;
            },
            console.error.bind(console, 'Cannot import key')
        );
    };

    AesCtr.prototype.update = function(bytes) {
        var self = this;
        var length = bytes.byteLength;

        return genKeyStream(this.key, this.counter, length, this.offset).then(
            function(keyStream) {
                var i;
                for (i = 0; i < length; i++) {
                    bytes[i] ^= keyStream[i];
                }

                // update offset
                self.offset = (self.offset + length) % 16;
                if (self.offset === 0) {
                    // update counter
                    for (i = 15; i > -1; i--) {
                        self.counter[i] += 1;
                        if (self.counter[i] !== 0) {
                            break;
                        }
                    }
                }
            },
            console.error.bind(console, 'genKeyStream error')
        );
    };

    window.AesCtr = AesCtr;
}());
