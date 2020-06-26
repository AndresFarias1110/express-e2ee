import * as CryptoJS from 'crypto-js';
import { ArrayUtils } from '../utils/array-utils';
import { sha256 } from 'js-sha256';
import { AlgoritmAES } from '../utils/aes-algoritm';

/**
 * Response e2e info process class to process when receive extrernal information
 */
export class E2EDecryption {
  /**
   * Char type => 'a': PIN, 'b': Password or 'c': Form data.
   * @example 'a'
   */
  private cType = '';
  /**
   * The server (back-end) random key generated.
   */
  private eventId: any;
  /**
   * The initialization vector generated from e2e encryption process.
   * @see E2eeEncryptionProcess
   */
  private ivVector: any;
  /**
   * The key-length used to encrypt and decrypt in AES algorithm.
   * @see E2eeEncryptionProcess
   */
  private ekVector: any;
  /**
   * The hmac key vector used to make hmac-sha256 algorithm.
   * @see E2eeEncryptionProcess
   */
  private hmacKeyVector: any;
  /**
   * The data entered by the user.
   */
  private data: any;
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
  doProcess = (cType: string, data: any, eventId: any, ivVector: any, ekVector: any, hmacKeyVector: any): object => {
    this.data = data;
    this.cType = cType;
    this.eventId = eventId;
    this.ivVector = ArrayUtils.convertHex().toBytes(ivVector);
    this.ekVector = ArrayUtils.convertHex().toBytes(ekVector);
    this.hmacKeyVector = ArrayUtils.convertHex().toBytes(hmacKeyVector);
    try {
      // Generate Client random string.
      const hexStrCR = ArrayUtils.generateRandomVector(128); // hexadecimal string 64-length
      const splitEvent = this.eventId.split('.');
      const chipherSRB64 = splitEvent[0];
      const chipherSRB64Final = chipherSRB64.replace(' ', '+');
      // Return base 64 object.
      const base64 = ArrayUtils.getBase64decode(chipherSRB64Final.toString());
      // Get WordArray to Uint8Array.
      const base64ToBytes = ArrayUtils.convertWordArrayToUint8Array(base64);
      // AES CBC Decryption using EK and IV vectors.
      const algoritAES = new AlgoritmAES();
      algoritAES.initAESAlgorithm(this.ekVector, this.ivVector, 'PKCS7');
      
      const sr = algoritAES.decrypt(base64ToBytes);
      // Skipping PKCS7 decrypted to unpad plaintext.
      const finalSR = ArrayUtils.convertUtf8().fromBytes(sr);
      // Concat HEXCR + SR + CSTYPE + DATA.
      const CSTYPE = this.cType;
      const CDATA = hexStrCR + finalSR + CSTYPE + this.data;
      const CDATABytes = ArrayUtils.convertUtf8().toBytes(CDATA);
      // AES CBC Encryption using EK and IV vectors.
      const eDataBytes = algoritAES.encrypt(CDATABytes);
      const eDataB64 = ArrayUtils.u8arrayToBase64(eDataBytes);
      // Hmac sha256 using eDataBytes and hmacKey vector.
      const hmac: number[] = this.hmacSha256(eDataBytes, this.hmacKeyVector);
      // Parse to base 64 string.
      const hmacB64 = ArrayUtils.convertU8arrayB64().parse(hmac).toString(CryptoJS.enc.Base64);
      return {
        encryptedPayload: `${eDataB64}.${hmacB64}`,
      };
    } catch (e) {
      return e;
    }
  }
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
  hmacSha256 = (message: string | any, key: string | any): number[] => {
    const hash = sha256.hmac.create(key).update(message);
    return hash.digest();
  }
}
