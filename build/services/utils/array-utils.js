"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ArrayUtils = void 0;
var CryptoJS = require('crypto-js');
/**
 * Array utils class to get common used functions to process arrays.
 */
var ArrayUtils = /** @class */ (function () {
    function ArrayUtils() {
    }
    /**
     * Checks if an array passed as an input has integers values and if it has non number values
     * returns false.
     * @param arrayish The array of characters to check
     */
    ArrayUtils.checkInts = function (arrayish) {
        if (!arrayish || !arrayish.length) {
            return false;
        }
        for (var index in arrayish) {
            if (!this.checkInt(arrayish[index]) || arrayish[index] < 0 || arrayish[index] > 255) {
                return false;
            }
        }
        return true;
    };
    /**
     * This parses/stringify between Uint8Array and WordArray object
     */
    ArrayUtils.convertU8arrayB64 = function () {
        /**
         * Converts a word array to a Uint8Array.
         * @param wordArray The word array.
         * @return The Uint8Array.
         * @example
         *     let u8arr = ArrayUtils.convertU8arrayB64().stringify(wordArray);
         */
        var stringify = function (wordArray) {
            // Shortcuts
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;
            // Convert
            var u8 = new Uint8Array(sigBytes);
            for (var i = 0; i < sigBytes; i++) {
                // tslint:disable-next-line: no-bitwise
                var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                u8[i] = byte;
            }
            return u8;
        };
        /**
         * Converts a Uint8Array to a word array.
         * @param u8Str The Uint8Array.
         * @return The word array
         * @example
         *     let wordArray = ArrayUtils.convertU8arrayB64().parse(u8arr);
         */
        var parse = function (u8arr) {
            // Shortcut
            var len = u8arr.length;
            // Convert
            var words = [];
            for (var i = 0; i < len; i++) {
                // tslint:disable-next-line: no-bitwise
                words[i >>> 2] |= (u8arr[i] & 0xff) << (24 - (i % 4) * 8);
            }
            return CryptoJS.lib.WordArray.create(words, len);
        };
        return { parse: parse, stringify: stringify };
    };
    /**
     * This checks if arg is a kind of Array
     * @param arg The parameter for check if it has Uint8Array format
     * @param copy The copy param for dividin an string 'arg' and parses to int array.
     */
    ArrayUtils.coerceArray = function (arg, copy) {
        // ArrayBuffer view
        if (arg.buffer && arg.name === 'Uint8Array') {
            if (copy) {
                if (arg.slice) {
                    arg = arg.slice();
                }
                else {
                    arg = Array.prototype.slice.call(arg);
                }
            }
            return arg;
        }
        // It's an array; check it is a valid representation of a byte
        if (Array.isArray(arg)) {
            if (!this.checkInts(arg)) {
                throw new Error("Array contains invalid value: " + arg);
            }
            return new Uint8Array(arg);
        }
        // Something else, but behaves like an array (maybe a Buffer? Arguments?)
        if (this.checkInt(arg.length) && this.checkInts(arg)) {
            return new Uint8Array(arg);
        }
        return new Uint8Array(arg);
    };
    /**
     * This is ued to converto to Utf8 or reverse.
     * @returns object
     */
    ArrayUtils.convertUtf8 = function () {
        var _this = this;
        /**
         * Used to parse an string of characters and converts to
         * an array of hexadecimal.
         * @param text The text to be parsed to bytes
         */
        var toBytes = function (text) {
            var result = [];
            var i = 0;
            text = encodeURI(text);
            while (i < text.length) {
                var c = text.charCodeAt(i);
                i++;
                if (c === 37) {
                    result.push(parseInt(text.substr(i, 2), 16));
                    i += 2;
                }
                else {
                    result.push(c);
                }
            }
            return _this.coerceArray(result);
        };
        /**
         * Used to parse from bytes array to string of chars.
         * @param bytes The array of chars used to parse to string
         */
        var fromBytes = function (bytes) {
            var result = [];
            var i = 0;
            while (i < bytes.length) {
                var c = bytes[i];
                if (c < 128) {
                    result.push(String.fromCharCode(c));
                    i++;
                }
                else if (c > 191 && c < 224) {
                    // tslint:disable-next-line: no-bitwise
                    result.push(String.fromCharCode(((c & 0x1f) << 6) | (bytes[i + 1] & 0x3f)));
                    i += 2;
                }
                else {
                    // tslint:disable-next-line: no-bitwise
                    result.push(String.fromCharCode(((c & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)));
                    i += 3;
                }
            }
            return result.join('');
        };
        return { toBytes: toBytes, fromBytes: fromBytes };
    };
    /**
     * Checks if char value is interger using parseInt function.
     * @param value The value to check if it is integer.
     */
    ArrayUtils.checkInt = function (value) {
        // tslint:disable-next-line: radix
        return parseInt(value) === value;
    };
    /**
     * This generates a random values in vector of blockSize / 8, then parses to hex string.
     * @example input:
     *  256
     * @example output:
     *  a5fd5a814a1e95ea3279e9634fc32987453ceda72ed0e13ba305f7db54c26e15
     * @param blockSize The block size of the random values of the vector
     */
    ArrayUtils.generateRandomVector = function (blockSize) {
        return CryptoJS.lib.WordArray.random(blockSize / 8).toString(CryptoJS.enc.Hex);
    };
    /**
     * This encodes a string to base 64 string UTF-8 format
     * @param textString The string to decode given as parameter
     */
    ArrayUtils.getBase64encode = function (textString) {
        var words = CryptoJS.enc.Utf8.parse(textString); // WordArray object
        return CryptoJS.enc.Base64.stringify(words);
    };
    /**
     * This decodes a base 64 string encoded
     * @param base64String The base 64 string encoded given as parameter
     */
    ArrayUtils.getBase64decode = function (base64String) {
        return CryptoJS.enc.Base64.parse(base64String);
    };
    /**
     * This parse an array buffer (e.g. Uint8Array, ArrayBuffer, etc.) to base 64 directly.
     * @param arrayBuffer The array buffer to be parsed.
     */
    ArrayUtils.u8arrayToBase64 = function (arrayBuffer) {
        var base64 = '';
        var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var bytes = new Uint8Array(arrayBuffer);
        var byteLength = bytes.byteLength;
        var byteRemainder = byteLength % 3;
        var mainLength = byteLength - byteRemainder;
        var a;
        var b;
        var c;
        var d;
        var chunk;
        // Main loop deals with bytes in chunks of 3
        for (var i = 0; i < mainLength; i = i + 3) {
            // Combine the three bytes into a single integer
            // tslint:disable-next-line: no-bitwise
            chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            // Use bitmasks to extract 6-bit segments from the triplet
            // tslint:disable-next-line: no-bitwise
            a = (chunk & 16515072) >> 18; // 16515072 = (2^6 - 1) << 18
            // tslint:disable-next-line: no-bitwise
            b = (chunk & 258048) >> 12; // 258048   = (2^6 - 1) << 12
            // tslint:disable-next-line: no-bitwise
            c = (chunk & 4032) >> 6; // 4032     = (2^6 - 1) << 6
            // tslint:disable-next-line: no-bitwise
            d = chunk & 63; // 63       = 2^6 - 1
            // Convert the raw binary segments to the appropriate ASCII encoding
            base64 += "" + encodings[a] + encodings[b] + encodings[c] + encodings[d];
        }
        // Deal with the remaining bytes and padding
        if (byteRemainder === 1) {
            chunk = bytes[mainLength];
            // tslint:disable-next-line: no-bitwise
            a = (chunk & 252) >> 2; // 252 = (2^6 - 1) << 2
            // Set the 4 least significant bits to zero
            // tslint:disable-next-line: no-bitwise
            b = (chunk & 3) << 4; // 3   = 2^2 - 1
            base64 += "" + encodings[a] + encodings[b] + "==";
        }
        else if (byteRemainder === 2) {
            // tslint:disable-next-line: no-bitwise
            chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
            // tslint:disable-next-line: no-bitwise
            a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10
            // tslint:disable-next-line: no-bitwise
            b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4
            // Set the 2 least significant bits to zero
            // tslint:disable-next-line: no-bitwise
            c = (chunk & 15) << 2; // 15    = 2^4 - 1
            base64 += "" + encodings[a] + encodings[b] + encodings[c] + "=";
        }
        return base64;
    };
    /**
     * This creates an array in Uint8Array Javascript type.
     * @example input:
     *  16
     * @example output:
     *  Uint8Array(16) [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
     * @param length The size of array of chars in Uint8Array format
     */
    ArrayUtils.createArray = function (length) {
        return new Uint8Array(length);
    };
    /**
     * This parse an string given as input, and returns an array in Uint8Array format.
     * Initializes an empty array, then, cast each substring of length 2 to a number in 16-base and
     * the final array result parse to Uint8Array.
     * @example input:
     * {
     *  words: [
     *  13142342,
     *  23434,
     *  23434,
     *  -234324,
     *  ...
     *  ],
     *  sigBytes: 16
     * }
     * @example output:
     *  Uint8Array(16) [32, 1, 114, 234, 122, 191, 56, 76, 99, 87, 100, 154, 120, 11, 45, 50]
     * @param input The input string to be parsed
     */
    ArrayUtils.convertWordArrayToUint8Array = function (wordArray) {
        var len = wordArray.words.length;
        // new Int8Array
        // tslint:disable-next-line: no-bitwise
        var finalU8Array = new Uint8Array(len << 2);
        var offset = 0;
        var word;
        for (var i = 0; i < len; i++) {
            word = wordArray.words[i];
            // tslint:disable-next-line: no-bitwise
            finalU8Array[offset] = word >> 24;
            offset++;
            // tslint:disable-next-line: no-bitwise
            finalU8Array[offset] = (word >> 16) & 0xff;
            offset++;
            // tslint:disable-next-line: no-bitwise
            finalU8Array[offset] = (word >> 8) & 0xff;
            offset++;
            // tslint:disable-next-line: no-bitwise
            finalU8Array[offset] = word & 0xff;
            offset++;
        }
        return finalU8Array;
    };
    /**
     * This parses to hexadecimal string or reverce process hex string to utf8.
     * @example output:
     *  {
     *   toBytes: [32, 32, 32, 32, 32, 32, 32, 32, 32, 32],
     *   fromBytes: 'ababababababbbaba'
     *  }
     */
    ArrayUtils.convertHex = function () {
        var Hex = '0123456789abcdef';
        /**
         * Parse an text to array of hexadecimal integers.
         * Inits an array called result.
         * For each 2-chars of 'text', parses in 16-radix that.
         * After that, return the result.
         * @example input:
         *   'ababababababababa'
         * @example output:
         *   [32, 32, 32, 32, 32, 32, 32, 32, 32]
         * @param text the text to be parsed
         */
        var toBytes = function (text) {
            var result = [];
            for (var i = 0; i < text.length; i += 2) {
                result.push(parseInt(text.substr(i, 2), 16));
            }
            return result;
        };
        /**
         * This is to parse array of integers (bytes) to hexadecimal string.
         * Inits an array called as result
         * For each array of bytes, parses to it equivalent hexadecimal char.
         * Concat the result array to string.
         * @example input:
         *   [32, 32, 32, 32, 32, 32, 32, 32, 32, 32,]
         * @example output:
         *   'abababababababababababababababab'
         * @param bytes The array of integer-bytes to be parsed to hexadecimal string.
         */
        var fromBytes = function (bytes) {
            var result = [];
            bytes.forEach(function (byte) {
                var v = byte;
                // tslint:disable-next-line: no-bitwise
                result.push(Hex[(v & 0xf0) >> 4] + Hex[v & 0x0f]);
            });
            return result.join('');
        };
        return { toBytes: toBytes, fromBytes: fromBytes };
    };
    return ArrayUtils;
}());
exports.ArrayUtils = ArrayUtils;
