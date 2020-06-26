"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.E2EDecryption = void 0;
var CryptoJS = require("crypto-js");
var array_utils_1 = require("../utils/array-utils");
var js_sha256_1 = require("js-sha256");
var aes_algoritm_1 = require("../utils/aes-algoritm");
/**
 * Response e2e info process class to process when receive extrernal information
 */
var E2EDecryption = /** @class */ (function () {
    function E2EDecryption() {
        var _this = this;
        /**
         * Char type => 'a': PIN, 'b': Password or 'c': Form data.
         * @example 'a'
         */
        this.cType = '';
        /**
         * @param algoritmAES Inject service encript AES
         */
        /**
         * To send encrypted information process method.
         * To create the payload where the AES encrypted text will be sent the next steps.
         * 1- Generate Client random as a random number of 32 characters and convert to HEX – CR.
         * 2- Retrieve Server Random 32 chars sent in the last response as described in the 'Obtaining
         *    SR from eventId' section- SR.
         * 3- Concatenate Client random, Server Random and data in the format - {CR + SR + CSTYPE + Data}.
         * 4- Encrypt this with the AES key using IV - Encrypt (CR + SR + CSTYPE + Data) with
         *    encryption key EK and using IV obtained with the POST request and then base 64 encode –
         *    eDataBytes.
         * 5- Generate HMAC256 of EDataBytes using HMAC key HK from POST Key invocation - HMAC(EDataBytes) – HMACBytes
         * 6- Perform a Base64 encoding of EDataBytes - EDATA_B64.
         * 7- Perfom a Base64 encoding of HMACBytes - HMAC_B64.
         * 8- Frame the final payload as {EDATA_B64.HMAC_B64} with a dot delimiter.
         * 9- return output
         * @example output:
         * {
         *   encryptedPayload:
         *      'xFAT/jxAQV5Doul4o2NR9WfhTu7eAFXH7BaXrASF42IHzfO+Ur1h3g5MvCZFvV+l3bLE+AB+nclEoIYEFHwzjNnwMQKe08SzcZeQstEdb4M=' +
         *      '.' +
         *      'nUFhOcYLoKhvpKTgngTPh5qmzXMM8Ug3hfAGb7CB/XM=', // Edata base64 + '.' + hmac base64
         * }
         * @param cType Char type => 'a': PIN, 'b': Password or 'c': Form data.
         * @param data The data entered by the user.
         * @param eventId The server random generated.
         * @param ivVector The initialization vector generated from e2e encryption process. @see E2eeEncryptionProcess.
         * @param ekVector The key-length used to encrypt and decrypt in AES algorithm.
         * @param hmacKeyVector The hmac key vector used to make hmac-sha256 algorithm.
         * @throws It is happened when AES algorithm or base 64 fails
         * @returns object
         */
        this.doProcess = function (cType, data, eventId, ivVector, ekVector, hmacKeyVector) {
            _this.data = data;
            _this.cType = cType;
            _this.eventId = eventId;
            _this.ivVector = array_utils_1.ArrayUtils.convertHex().toBytes(ivVector);
            _this.ekVector = array_utils_1.ArrayUtils.convertHex().toBytes(ekVector);
            _this.hmacKeyVector = array_utils_1.ArrayUtils.convertHex().toBytes(hmacKeyVector);
            try {
                // Generate Client random string.
                var hexStrCR = array_utils_1.ArrayUtils.generateRandomVector(128); // hexadecimal string 64-length
                var splitEvent = _this.eventId.split('.');
                var chipherSRB64 = splitEvent[0];
                var chipherSRB64Final = chipherSRB64.replace(' ', '+');
                // Return base 64 object.
                var base64 = array_utils_1.ArrayUtils.getBase64decode(chipherSRB64Final.toString());
                // Get WordArray to Uint8Array.
                var base64ToBytes = array_utils_1.ArrayUtils.convertWordArrayToUint8Array(base64);
                // AES CBC Decryption using EK and IV vectors.
                var algoritAES = new aes_algoritm_1.AlgoritmAES();
                algoritAES.initAESAlgorithm(_this.ekVector, _this.ivVector, 'PKCS7');
                var sr = algoritAES.decrypt(base64ToBytes);
                // Skipping PKCS7 decrypted to unpad plaintext.
                var finalSR = array_utils_1.ArrayUtils.convertUtf8().fromBytes(sr);
                // Concat HEXCR + SR + CSTYPE + DATA.
                var CSTYPE = _this.cType;
                var CDATA = hexStrCR + finalSR + CSTYPE + _this.data;
                var CDATABytes = array_utils_1.ArrayUtils.convertUtf8().toBytes(CDATA);
                // AES CBC Encryption using EK and IV vectors.
                var eDataBytes = algoritAES.encrypt(CDATABytes);
                var eDataB64 = array_utils_1.ArrayUtils.u8arrayToBase64(eDataBytes);
                // Hmac sha256 using eDataBytes and hmacKey vector.
                var hmac = _this.hmacSha256(eDataBytes, _this.hmacKeyVector);
                // Parse to base 64 string.
                var hmacB64 = array_utils_1.ArrayUtils.convertU8arrayB64().parse(hmac).toString(CryptoJS.enc.Base64);
                return {
                    encryptedPayload: eDataB64 + "." + hmacB64,
                };
            }
            catch (e) {
                return e;
            }
        };
        /**
         * To get HmacSha256 funtion has algorithm.
         * @example input params:
         *  message: ArrayBuffer = [
         *   -111, -77, 80, -120, 127, -42, 38, 25, 27, 98, 86,
         *   59, 78, 121, 30, 111, 74, 108, -67, 120, 87, 79,
         *   127, 120, -105, 114, 80, -9, 57, -11, 113, -47, 82,
         *   81, 83, -116, -17, 109, 35, 38, -73, 75, -42, -25,
         *   -121, 100, 71, 111, -92, -6, 70, -33, -17, 53,
         *   -35, -92, -20, 126, 16, 101, -42, -75, 109, -40, 51,
         *   89, 100, 54, -101, -114,  75, 39, 50, 125, 109, 48,
         *   -120, -59, 53, 88
         *  ]
         *  key: ArrayBuffer = [
         *   -44, -105, 79, 2, -110, -22, -3, 56, 56, 115, -75,
         *   -19, 68, 37, 22, 1, -86, 42, -31, -70, 69, -44, -30,
         *   -34, - 53, 36, -49, -124, 45, -69, 52, -85
         *  ]
         * @example output value:
         *  '+KRSM9tVqrs4AsZJi6yAkQ2tlFnRo8VlBwf27BOOwBM='
         * @param message The input to get hmacsha256 algorithm
         * @returns Array<number>
         */
        this.hmacSha256 = function (message, key) {
            var hash = js_sha256_1.sha256.hmac.create(key).update(message);
            return hash.digest();
        };
    }
    return E2EDecryption;
}());
exports.E2EDecryption = E2EDecryption;
