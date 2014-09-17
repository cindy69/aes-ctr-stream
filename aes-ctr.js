(function() {
    function AesEcb(key, plaintext) {
        return crypto.subtle.encrypt(
            {name: 'aes-cbc', iv: new Uint8Array(16)},
            key,
            plaintext
        );
    }

    function genBlock(key, counter) {
        return AesEcb(key, counter).then(
            function(ciphertext) {
                // update counter
                var i;
                for (i = counter.byteLength - 1; i > -1; i--) {
                    counter[i] += 1;
                    if (counter[i] != 0) {
                        break;
                    }
                }
                return new Uint8Array(ciphertext);
            },
            console.error.bind(console, 'AesEcb error')
        );
    }


    var AesCtr = function() {};

    AesCtr.prototype.init = function(keyData, initCtr) {
        this.counter = initCtr;

        var self = this;

        return crypto.subtle.importKey(
            'raw', keyData,
            {name: 'aes-cbc', iv: new Uint8Array(16)},
            true, ['encrypt']
        ).then(
            function(key) {
                self.key = key;
                return genBlock(self.key, self.counter);
            },
            console.error.bind(console, 'Cannot import key')
        ).then(
            function(ciphertext) {
                self.offset = 0;
                self.stream = ciphertext;
            },
            console.error.bind(console, 'genBlock error')
        );
    };

    AesCtr.prototype.update = function(bytes) {
        var self = this;

        function updateByte(idx) {
            bytes[idx] ^= self.stream[self.offset++];
            
            if (self.offset === 16) {
                return genBlock(self.key, self.counter).then(
                    function(ciphertext) {
                        self.offset = 0;
                        self.stream = ciphertext;
                        return idx + 1;
                    },
                    console.error.bind(console, 'genBlock error')
                )
            }

            return idx + 1;
        }

        var i, sequence = Promise.resolve(0);
        for (i = 0; i < bytes.byteLength; i++) {
            sequence = sequence.then(
                updateByte,
                console.error.bind(console, 'sequence error')
            );
        }

        return sequence;
    };

    window.AesCtr = AesCtr;
}());
