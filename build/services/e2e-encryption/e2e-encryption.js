"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.E2eEncryption = void 0;
var array_utils_1 = require("../utils/array-utils");
var rsa_algoritm_1 = require("../utils/rsa-algoritm");
var aes_algoritm_1 = require("../utils/aes-algoritm");
/**
 * The process class used to make process for /security/e2ee/key - POST
 */
var E2eEncryption = /** @class */ (function () {
    function E2eEncryption() {
        var _this = this;
        /**
         * To make e2e encryption text
         * 1- Checks if any public key is set
         * 2- Generates AES 64bits key  - EK
         * 3- Generates initial vector of 3bits size
         * 4- Generates AES 64bits key  - HK
         * 5- Concat EK + IV + HK
         * 6- Encrypt hexadecimal string from step 5
         * 7- AES encryption for 16-blank spaces using EK key and IV
         * 8- AES encryption for 16-blank spaces using HK key and IV
         * 9- return output
         * @example output:
         * {
         *   algorithm: 'AES',
         *   encryptedPayload: 'a5fd5a814a1e95ea3279e9634fc32987453ceda72ed0e13ba305f7db54c26e15', // ekCheckDigit
         *   encKeyCheckDigit: 'ABCD13'
         *   hmacKeyCheckDigit: '1EBC7A', // hkCheckDigit
         * }
         * @throws Error if public key is not set
         * @returns void
         */
        this.doProcess = function (publicKey) {
            _this.publicKey = publicKey;
            // Generate AES 256 size bit, then parse to hex string - EK
            _this.encryptionKeyVector = array_utils_1.ArrayUtils.generateRandomVector(256);
            var EKBytes = array_utils_1.ArrayUtils.convertHex().toBytes(_this.encryptionKeyVector);
            // Generate IV randomly, then parse to hex string - IV
            _this.initializationVector = array_utils_1.ArrayUtils.generateRandomVector(128);
            var IVBytes = array_utils_1.ArrayUtils.convertHex().toBytes(_this.initializationVector);
            // Generate AES 256 size bit, then parse to hex string - HK
            _this.hmacKeyVector = array_utils_1.ArrayUtils.generateRandomVector(256);
            var HKBytes = array_utils_1.ArrayUtils.convertHex().toBytes(_this.hmacKeyVector);
            // Concat EK + IV + HK => CAT
            var CAT = "" + _this.encryptionKeyVector + _this.initializationVector + _this.hmacKeyVector;
            // Encrypt with RSA algorithm CAT with public key got from step 1 => RSACAT
            _this.algorithm = new rsa_algoritm_1.AlgoritmRSA();
            _this.algorithm.setKey({
                m: _this.publicKey.modulus,
                e: _this.publicKey.exponent,
            });
            _this.algorithm.setMessage(CAT.toString());
            _this.algorithm.encrypt();
            var RSACAT = _this.algorithm.getCipherText();
            // Parse RSACAT to hex string - encrypted payload
            var encryptedHexPayload = RSACAT.toString();
            var _a = _this, ek = _a.encryptionKeyVector, iv = _a.initializationVector, hk = _a.hmacKeyVector;
            return {
                e2eVectors: { ek: ek, iv: iv, hk: hk },
                payload: {
                    algorithm: 'AES',
                    encryptedPayload: encryptedHexPayload,
                    encKeyCheckDigit: _this.encriptAES(EKBytes, IVBytes),
                    hmacKeyCheckDigit: _this.encriptAES(HKBytes, IVBytes),
                },
            };
        };
        /**
         * @param key The symetric key used for encryption/decryption process
         * @param iv The initialization vector used for any operation mode
         */
        this.encriptAES = function (key, iv) {
            var blankSpaces = new Array(17).join(' ').toString();
            _this.algorithm = new aes_algoritm_1.AlgoritmAES();
            _this.algorithm.initAESAlgorithm(key, iv);
            var result = _this.algorithm.encrypt(array_utils_1.ArrayUtils.convertUtf8().toBytes(blankSpaces));
            return array_utils_1.ArrayUtils.convertHex().fromBytes(result).substring(0, 6);
        };
    }
    return E2eEncryption;
}());
exports.E2eEncryption = E2eEncryption;
