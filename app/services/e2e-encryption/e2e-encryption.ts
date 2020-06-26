import { ArrayUtils } from '../utils/array-utils';
import { AlgoritmRSA } from '../utils/rsa-algoritm';
import { AlgoritmAES } from '../utils/aes-algoritm';

/**
 * The process class used to make process for /security/e2ee/key - POST
 */
export class E2eEncryption {
  /**
   * The public key encryption/decryption process
   * @example value:
   *  {
   *   'modulus': 'ABABABABABABABABBAABABABABABABABABBA2323B0B0B0B0B1010101',
   *   'exponent': '10001',
   *  }
   */
  private publicKey: any;
  /**
   * The algorithm using cipher factory instances RSA or AES or AES CBC mode
   */
  private algorithm: any;
  /**
   * encryptionKeyVector
   */
  private encryptionKeyVector: any;
  /**
   * initializationVector
   */
  private initializationVector: any;
  /**
   * hmacKeyVector
   */
  private hmacKeyVector: any;
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
  public doProcess = (publicKey: any): object => {
    this.publicKey = publicKey;
    // Generate AES 256 size bit, then parse to hex string - EK
    this.encryptionKeyVector = ArrayUtils.generateRandomVector(256);
    const EKBytes = ArrayUtils.convertHex().toBytes(this.encryptionKeyVector);
    // Generate IV randomly, then parse to hex string - IV
    this.initializationVector = ArrayUtils.generateRandomVector(128);
    const IVBytes = ArrayUtils.convertHex().toBytes(this.initializationVector);
    // Generate AES 256 size bit, then parse to hex string - HK
    this.hmacKeyVector = ArrayUtils.generateRandomVector(256);
    const HKBytes = ArrayUtils.convertHex().toBytes(this.hmacKeyVector);
    // Concat EK + IV + HK => CAT
    const CAT = `${this.encryptionKeyVector}${this.initializationVector}${this.hmacKeyVector}`;
    // Encrypt with RSA algorithm CAT with public key got from step 1 => RSACAT
    this.algorithm = new AlgoritmRSA();
    this.algorithm.setKey({
      m: this.publicKey.modulus,
      e: this.publicKey.exponent,
    });
    this.algorithm.setMessage(CAT.toString());
    this.algorithm.encrypt();
    const RSACAT = this.algorithm.getCipherText();
    // Parse RSACAT to hex string - encrypted payload
    const encryptedHexPayload = RSACAT.toString();
    const { encryptionKeyVector: ek, initializationVector: iv, hmacKeyVector: hk } = this;
    return {
      e2eVectors: { ek, iv, hk },
      payload: {
        algorithm: 'AES', // algorithm 'AES'
        encryptedPayload: encryptedHexPayload,
        encKeyCheckDigit:  this.encriptAES(EKBytes, IVBytes),  // ekCheckDigit
        hmacKeyCheckDigit: this.encriptAES(HKBytes, IVBytes), // hkCheckDigit
      },
    };
  }
  /**
   * @param key The symetric key used for encryption/decryption process
   * @param iv The initialization vector used for any operation mode
   */
  encriptAES = (key: any, iv: any) => {
    const blankSpaces = new Array(17).join(' ').toString();
    this.algorithm = new AlgoritmAES();
    this.algorithm.initAESAlgorithm(key, iv);
    const result = this.algorithm.encrypt(ArrayUtils.convertUtf8().toBytes(blankSpaces));
    return ArrayUtils.convertHex().fromBytes(result).substring(0, 6);
  }
}

