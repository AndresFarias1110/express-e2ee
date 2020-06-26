var forge = require('node-forge');
var secureRandom = require('secure-random');

/**
 * Declare BigInteger type class
 */
const BigInteger = forge.jsbn.BigInteger;

/**
 * The RSA object class to implement RSA algorithm
 */
export class AlgoritmRSA {
  /**
   * The object instance of RSA bignumber library using RSA algorithm
   */
  private publ: any;
  /**
   * The message to be encrypted using RSA.
   */
  private message = '';
  /**
   * The ciphertext to be decrypted using RSA.
   */
  private cipherText = '';

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
  public pkcs1Padding = (plainText: string, modulusBitLength: number) => {
    if (modulusBitLength < plainText.length + 11) {
      throw new Error(`Message too long for RSA (n=${modulusBitLength}, l=${plainText.length})`);
    }
    const plainTextPadded = new Array();
    let i = plainText.length - 1; // index pointer to plainText
    // insert data (plainText) at the end of the array (plainTextPadded)
    while (i >= 0 && modulusBitLength > 0) {
      const c = plainText.charCodeAt(i);
      i --;
      if (c < 128) {
        // encode using utf-8
        plainTextPadded[modulusBitLength - 1] = c;
        --modulusBitLength;
      } else if (c > 127 && c < 2048) {
        // tslint:disable-next-line: no-bitwise
        plainTextPadded[modulusBitLength - 1] = (c & 63) | 128;
        --modulusBitLength;
        // tslint:disable-next-line: no-bitwise
        plainTextPadded[modulusBitLength - 1] = (c >> 6) | 192;
        --modulusBitLength;
      } else {
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
    let randomBytes = new Array();
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
  }

  /**
   * (message ^ exponent) mod modulus.
   *
   * @param message The message to be encrypted using RSA
   */
  public modularExponenciation = (message: { modPowInt: (arg0: any, arg1: any) => void }): any => {
    return message.modPowInt(this.publ.exponent, this.publ.modulus);
  }

  /**
   * The public key for encryption/decryption process
   * @param publicKey The public key to be used for encryption
   */
  public setKey = (publicKey: any): void => {
    this.publ = {
      modulus: new BigInteger(publicKey.m, 16),
      exponent: new BigInteger(publicKey.e, 16),
    };
  }

  /**
   * This gets de public key
   * @example output:
   *  {
   *    m: 'BDFE22478847948432342348',
   *    e: '10001' => 65537 // 2 ^ 17 + 1
   *  }
   */
  public getKey = (): any => {
    return {
      m: this.publ.modulus.toString(16),
      e: this.publ.exponent.toString(16),
    };
  }

  /**
   * Sets the plain text
   * @param message The message to be used for encrypting/decrypting
   * @returns void
   */
  public setMessage = (message: string): void => {
    this.message = message;
  }

  /**
   * Gets the plain text
   * @returns string plain text
   */
  public getMessage = (): string => {
    return this.message;
  }
  /**
   * This gets the ciphertext encrypted from RSA algorithm
   * @returns string The ciphertext encrypted
   */
  public getCipherText = (): string => {
    return this.cipherText;
  }
  /**
   * This method is used for encryption when client sets a public key from setPublicKey method
   * @throws Error throws an error if message field plaintext is not set or null
   * @example
   *  RSAEncryption('some text') => '0e04020f0a28937823'
   * @returns void
   */
  public encrypt = (): void => {
    if (!this.getMessage()) {
      throw new Error('Message must be set in object to encrypt');
    }
    // tslint:disable-next-line: no-bitwise
    const paddedMessage = this.pkcs1Padding(this.getMessage(), (this.publ.modulus.bitLength() + 7) >> 3);
    const encryptedText = this.modularExponenciation(paddedMessage); // encryption using public key (m, e)
    const encryptedTextHex = encryptedText.toString(16);
    // if ciphertext length is odd, append at the beginning '0')
    // tslint:disable-next-line: no-bitwise
    const encryptedInformation = (encryptedTextHex.length & 1) === 0 ? encryptedTextHex : `0${encryptedTextHex}`;
    this.cipherText = encryptedInformation;
  }
}
