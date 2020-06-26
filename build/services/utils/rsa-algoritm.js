"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlgoritmRSA = void 0;
var forge = require('node-forge');
var secureRandom = require('secure-random');
/**
 * Declare BigInteger type class
 */
var BigInteger = forge.jsbn.BigInteger;
/**
 * The RSA object class to implement RSA algorithm
 */
var AlgoritmRSA = /** @class */ (function () {
    function AlgoritmRSA() {
        var _this = this;
        /**
         * The message to be encrypted using RSA.
         */
        this.message = '';
        /**
         * The ciphertext to be decrypted using RSA.
         */
        this.cipherText = '';
        /**
         * (PKCS#1 algorithm type 2)
         * data = ' ---- data ----'
         * Padded text = | 0x00 | 0x02 | ------ random bytes -------- | 0x00 | ----- data ----- |
         *
         * To pad any text using standard PKCS#1 algorithm
         * 1- Check if modulus length is less then plain text length.
         * 2- Create a new array to insert data (plainText) at the end of the array.
         * 3- Add random bytes
         * 4- At plainTextPadded[1] assign => 2
         * 5- At plainTextPadded[0] assign => 0
         * @param plainText The text to be padded using PKCS#1 v2.0.
         * @param modulusBitLength The modulus length bytes, so that, RSA modulus is a BigInteger
         * @example
         *  let paddedText: BigInteger = pkcs1pad2('some text', modulus.length >> 3)
         */
        this.pkcs1Padding = function (plainText, modulusBitLength) {
            if (modulusBitLength < plainText.length + 11) {
                throw new Error("Message too long for RSA (n=" + modulusBitLength + ", l=" + plainText.length + ")");
            }
            var plainTextPadded = new Array();
            var i = plainText.length - 1; // index pointer to plainText
            // insert data (plainText) at the end of the array (plainTextPadded)
            while (i >= 0 && modulusBitLength > 0) {
                var c = plainText.charCodeAt(i);
                i--;
                if (c < 128) {
                    // encode using utf-8
                    plainTextPadded[modulusBitLength - 1] = c;
                    --modulusBitLength;
                }
                else if (c > 127 && c < 2048) {
                    // tslint:disable-next-line: no-bitwise
                    plainTextPadded[modulusBitLength - 1] = (c & 63) | 128;
                    --modulusBitLength;
                    // tslint:disable-next-line: no-bitwise
                    plainTextPadded[modulusBitLength - 1] = (c >> 6) | 192;
                    --modulusBitLength;
                }
                else {
                    // tslint:disable-next-line: no-bitwise
                    plainTextPadded[modulusBitLength - 1] = (c & 63) | 128;
                    --modulusBitLength;
                    // tslint:disable-next-line: no-bitwise
                    plainTextPadded[modulusBitLength - 1] = ((c >> 6) & 63) | 128;
                    --modulusBitLength;
                    // tslint:disable-next-line: no-bitwise
                    plainTextPadded[modulusBitLength - 1] = (c >> 12) | 224;
                    --modulusBitLength;
                }
            }
            plainTextPadded[modulusBitLength - 1] = 0; // append 0x00 before doing random bytes
            --modulusBitLength;
            // do random bytes
            var randomBytes = new Array();
            while (modulusBitLength > 2) {
                // random non-zero pad
                randomBytes[0] = 0;
                while (randomBytes[0] === 0) {
                    randomBytes = secureRandom.randomArray(randomBytes.length);
                }
                plainTextPadded[modulusBitLength - 1] = randomBytes[0];
                --modulusBitLength;
            }
            plainTextPadded[modulusBitLength - 1] = 2; // append 0x02 after doing random bytes
            --modulusBitLength;
            plainTextPadded[modulusBitLength - 1] = 0; // append 0x00 after append 0x02
            return new BigInteger(plainTextPadded);
        };
        /**
         * (message ^ exponent) mod modulus.
         *
         * @param message The message to be encrypted using RSA
         */
        this.modularExponenciation = function (message) {
            return message.modPowInt(_this.publ.exponent, _this.publ.modulus);
        };
        /**
         * The public key for encryption/decryption process
         * @param publicKey The public key to be used for encryption
         */
        this.setKey = function (publicKey) {
            _this.publ = {
                modulus: new BigInteger(publicKey.m, 16),
                exponent: new BigInteger(publicKey.e, 16),
            };
        };
        /**
         * This gets de public key
         * @example output:
         *  {
         *    m: 'BDFE22478847948432342348',
         *    e: '10001' => 65537 // 2 ^ 17 + 1
         *  }
         */
        this.getKey = function () {
            return {
                m: _this.publ.modulus.toString(16),
                e: _this.publ.exponent.toString(16),
            };
        };
        /**
         * Sets the plain text
         * @param message The message to be used for encrypting/decrypting
         * @returns void
         */
        this.setMessage = function (message) {
            _this.message = message;
        };
        /**
         * Gets the plain text
         * @returns string plain text
         */
        this.getMessage = function () {
            return _this.message;
        };
        /**
         * This gets the ciphertext encrypted from RSA algorithm
         * @returns string The ciphertext encrypted
         */
        this.getCipherText = function () {
            return _this.cipherText;
        };
        /**
         * This method is used for encryption when client sets a public key from setPublicKey method
         * @throws Error throws an error if message field plaintext is not set or null
         * @example
         *  RSAEncryption('some text') => '0e04020f0a28937823'
         * @returns void
         */
        this.encrypt = function () {
            if (!_this.getMessage()) {
                throw new Error('Message must be set in object to encrypt');
            }
            // tslint:disable-next-line: no-bitwise
            var paddedMessage = _this.pkcs1Padding(_this.getMessage(), (_this.publ.modulus.bitLength() + 7) >> 3);
            var encryptedText = _this.modularExponenciation(paddedMessage); // encryption using public key (m, e)
            var encryptedTextHex = encryptedText.toString(16);
            // if ciphertext length is odd, append at the beginning '0')
            // tslint:disable-next-line: no-bitwise
            var encryptedInformation = (encryptedTextHex.length & 1) === 0 ? encryptedTextHex : "0" + encryptedTextHex;
            _this.cipherText = encryptedInformation;
        };
    }
    return AlgoritmRSA;
}());
exports.AlgoritmRSA = AlgoritmRSA;
