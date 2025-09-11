const ADSCORE_ZONE_REQUEST_KEY = "OO1GdoBz0RjUW9d7\/gTJ+Kk0bNZJn3y24M2kpwROaUI=";
const ALLOWED_VERDICTS = ["ok"];
const ADSCORE_ZONE_API_KEY = "QrfeBAAAAAAAGPqEPRI6wy997xQpxmyFaK-Ru2E";
const ADSCORE_ZONE_RESPONSE_KEY = "JdsAWywdJ\/DHAtj\/o807dO7u8zjUfMQ02oJDJJWBP1g=";

class AdscoreError extends Error {
    constructor(message, cause) {
        // @ts-ignore cause is supported from ES2022 and this package targets ES2016
        super(message, { cause });
    }
}

class InvalidArgumentError extends AdscoreError {
}

function substrBinary(input, offset, length) {
    if (length !== undefined) {
        return input.slice(offset, offset + length);
    }
    return input.slice(offset);
}

/**
 * Partial Buffer.js polyfill
 * From: https://github.com/feross/buffer
 * MIT License: https://github.com/feross/buffer?tab=License-1-ov-file#readme
 */
class ByteOperations extends Uint8Array {
    writeInt8(value, offset = 0, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert)
            this.checkInt(this, value, offset, 1, 0x7f, -0x80);
        if (value < 0)
            value = 0xff + value + 1;
        this[offset] = value & 0xff;
        return offset + 1;
    }
    writeUInt8(value, offset = 0, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert)
            this.checkInt(this, value, offset, 1, 0xff, 0);
        this[offset] = value & 0xff;
        return offset + 1;
    }
    writeInt16BE(value, offset = 0, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert)
            this.checkInt(this, value, offset, 2, 0x7fff, -0x8000);
        this[offset] = value >>> 8;
        this[offset + 1] = value & 0xff;
        return offset + 2;
    }
    writeUInt32BE(value, offset = 0, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert)
            this.checkInt(this, value, offset, 4, 0xffffffff, 0);
        this[offset] = value >>> 24;
        this[offset + 1] = value >>> 16;
        this[offset + 2] = value >>> 8;
        this[offset + 3] = value & 0xff;
        return offset + 4;
    }
    writeBigUInt64BE(value, offset = 0) {
        return this.wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
    }
    writeInt16LE(value, offset = 0, noAssert) {
        value = +value;
        offset = offset >>> 0;
        if (!noAssert)
            this.checkInt(this, value, offset, 2, 0x7fff, -0x8000);
        this[offset] = value & 0xff;
        this[offset + 1] = value >>> 8;
        return offset + 2;
    }
    readInt8(offset = 0, noAssert) {
        offset = offset >>> 0;
        if (!noAssert)
            this.checkOffset(offset, 1, this.length);
        if (!(this[offset] & 0x80))
            return this[offset];
        return (0xff - this[offset] + 1) * -1;
    }
    readUInt8(offset = 0, noAssert) {
        offset = offset >>> 0;
        if (!noAssert)
            this.checkOffset(offset, 1, this.length);
        return this[offset];
    }
    readInt16BE(offset = 0, noAssert) {
        offset = offset >>> 0;
        if (!noAssert)
            this.checkOffset(offset, 2, this.length);
        const val = this[offset + 1] | (this[offset] << 8);
        return val & 0x8000 ? val | 0xffff0000 : val;
    }
    readUInt32BE(offset = 0, noAssert) {
        offset = offset >>> 0;
        if (!noAssert)
            this.checkOffset(offset, 4, this.length);
        return (this[offset] * 0x1000000 +
            ((this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3]));
    }
    readInt16LE(offset = 0, noAssert) {
        offset = offset >>> 0;
        if (!noAssert)
            this.checkOffset(offset, 2, this.length);
        const val = this[offset] | (this[offset + 1] << 8);
        return val & 0x8000 ? val | 0xffff0000 : val;
    }
    readBigUInt64BE(offset = 0) {
        offset = offset >>> 0;
        this.validateNumber(offset, "offset");
        const first = this[offset];
        const last = this[offset + 7];
        if (first === undefined || last === undefined) {
            throw new Error("Out of bounds");
        }
        const hi = first * 2 ** 24 +
            this[++offset] * 2 ** 16 +
            this[++offset] * 2 ** 8 +
            this[++offset];
        const lo = this[++offset] * 2 ** 24 +
            this[++offset] * 2 ** 16 +
            this[++offset] * 2 ** 8 +
            last;
        return (BigInt(hi) << BigInt(32)) + BigInt(lo);
    }
    validateNumber(value, name) {
        if (typeof value !== "number") {
            throw new Error("Invalid arg type");
        }
    }
    checkBounds(buf, offset, byteLength) {
        this.validateNumber(offset, "offset");
        if (buf[offset] === undefined || buf[offset + byteLength] === undefined) {
            throw new Error("Out of bounds");
        }
    }
    checkIntBI(value, min, max, buf, offset, byteLength) {
        if (value > max || value < min) {
            if (byteLength > 3) {
                if (min === 0n || min === BigInt(0)) ;
            }
            throw new Error("Out of range");
        }
        this.checkBounds(buf, offset, byteLength);
    }
    wrtBigUInt64BE(buf, value, offset, min, max) {
        this.checkIntBI(value, min, max, buf, offset, 7);
        let lo = Number(value & BigInt(0xffffffff));
        buf[offset + 7] = lo;
        lo = lo >> 8;
        buf[offset + 6] = lo;
        lo = lo >> 8;
        buf[offset + 5] = lo;
        lo = lo >> 8;
        buf[offset + 4] = lo;
        let hi = Number((value >> BigInt(32)) & BigInt(0xffffffff));
        buf[offset + 3] = hi;
        hi = hi >> 8;
        buf[offset + 2] = hi;
        hi = hi >> 8;
        buf[offset + 1] = hi;
        hi = hi >> 8;
        buf[offset] = hi;
        return offset + 8;
    }
    checkInt(buf, value, offset, ext, max, min) {
        if (value > max || value < min)
            throw new RangeError('"value" argument is out of bounds');
        if (offset + ext > buf.length)
            throw new RangeError("Index out of range");
    }
    boundsError(value, length, type) {
        if (Math.floor(value) !== value) {
            this.validateNumber(value, type);
            throw new Error(`Out of range`);
        }
        if (length < 0) {
            throw new Error("Out of bounds");
        }
        throw new Error("Out of range");
    }
    checkOffset(offset, ext, length) {
        if (offset % 1 !== 0 || offset < 0)
            throw new RangeError("offset is not uint");
        if (offset + ext > length)
            throw new RangeError("Trying to access beyond buffer length");
    }
}

function contactUint8Array(elements) {
    const totalLength = elements.reduce((prev, curr) => {
        prev += curr.length;
        return prev;
    }, 0);
    const result = new Uint8Array(totalLength);
    let pos = 0;
    for (let index = 0; index < elements.length; index++) {
        const element = elements[index];
        result.set(element, pos);
        pos += element.length;
    }
    return result;
}

/**
 * Partial Implementation of PHP's `pack`, see https://www.php.net/manual/en/function.pack
 */
function pack(format, ...inputs) {
    const instructions = format?.split("");
    if (instructions.length !== inputs.length) {
        throw new Error(`Invalid format length, expected ${inputs.length} number of codes`);
    }
    const result = [];
    for (let i = 0; i < inputs.length; i++) {
        const { code, name } = getCodeAndName$1(instructions[i]);
        const encodedData = encode(inputs[i], code);
        result.push(encodedData);
    }
    return contactUint8Array(result);
}
function encode(input, code) {
    switch (code) {
        // signed char
        case "c":
            throwIfBigInt(input, "char");
            const c = new ByteOperations(new Uint8Array(1));
            c.writeInt8(input);
            return c;
        // unsigned char
        case "C":
            throwIfBigInt(input, "char");
            const C = new ByteOperations(new Uint8Array(1));
            C.writeUInt8(input);
            return C;
        // unsigned short (always 16 bit, big endian byte order)
        case "n":
            throwIfBigInt(input, "short");
            const n = new ByteOperations(new Uint8Array(2));
            n.writeInt16BE(input);
            return n;
        // 	unsigned long (always 32 bit, big endian byte order)
        case "N":
            throwIfBigInt(input, "short");
            const N = new ByteOperations(new Uint8Array(4));
            N.writeUInt32BE(input);
            return N;
        // unsigned long long (always 64 bit, big endian byte order)
        case "J":
            const j = new ByteOperations(new Uint8Array(8));
            j.writeBigUInt64BE(BigInt(input));
            return j;
        // 	unsigned short (always 16 bit, little endian byte order)
        case "v":
            throwIfBigInt(input, "short");
            const v = new ByteOperations(new Uint8Array(2));
            v.writeInt16LE(input);
            return v;
    }
    throw new Error(`Unrecognized instruction: ${code}`);
}
function throwIfBigInt(input, type) {
    if (typeof input === "bigint") {
        throw new Error("Cannot write bigint into " + type);
    }
}
function getCodeAndName$1(instruction) {
    if (!instruction?.length) {
        throw new Error("Empty instruction");
    }
    return {
        code: instruction.charAt(0),
        name: instruction.substring(1),
    };
}

function arraySum(input) {
    const data = Object.values(input);
    return data.reduce((prev, curr) => (curr += prev));
}

/**
 * Partial Implementation of PHP's `unpack`, see https://www.php.net/manual/en/function.unpack
 */
function unpack(format, input) {
    const instructions = format?.split("/");
    let currentBytesOffset = 0;
    const result = {};
    for (const instruction of instructions) {
        const { code, name } = getCodeAndName(instruction);
        const { bytesOffset, decodedData } = decode(input, code, currentBytesOffset);
        currentBytesOffset += bytesOffset;
        result[name] = decodedData;
    }
    return result;
}
function decode(input, code, offset) {
    if (offset > input.length) {
        throw new Error(`Buffer overflow. Current: ${input.length}, requested: ${offset}`);
    }
    switch (code) {
        // signed char
        case "c":
            return {
                bytesOffset: 1,
                decodedData: new ByteOperations(input).readInt8(offset),
            };
        // unsigned char
        case "C":
            return {
                bytesOffset: 1,
                decodedData: new ByteOperations(input).readUInt8(offset),
            };
        // unsigned short (always 16 bit, big endian byte order)
        case "n":
            return {
                bytesOffset: 2,
                decodedData: new ByteOperations(input).readInt16BE(offset),
            };
        // 	unsigned long (always 32 bit, big endian byte order)
        case "N":
            return {
                bytesOffset: 4,
                decodedData: new ByteOperations(input).readUInt32BE(offset),
            };
        // unsigned long long (always 64 bit, big endian byte order)
        case "J":
            return {
                bytesOffset: 8,
                decodedData: new ByteOperations(input).readBigUInt64BE(offset),
            };
        // 	unsigned short (always 16 bit, little endian byte order)
        case "v":
            return {
                bytesOffset: 2,
                decodedData: new ByteOperations(input).readInt16LE(offset),
            };
    }
    throw new Error(`Unrecognized instruction: ${code}`);
}
function getCodeAndName(instruction) {
    if (!instruction?.length) {
        throw new Error("Empty instruction");
    }
    return {
        code: instruction.charAt(0),
        name: instruction.substring(1),
    };
}

class CryptParseError extends Error {
}

class AbstractSymmetricCrypt {
    parse(payload, lengths) {
        if (payload.length <
            AbstractSymmetricCrypt.METHOD_SIZE + arraySum(lengths)) {
            throw new CryptParseError("Premature data end");
        }
        let pos = AbstractSymmetricCrypt.METHOD_SIZE;
        const result = unpack("vmethod", substrBinary(payload, 0, pos));
        for (const [key, length] of Object.entries(lengths)) {
            result[key] = substrBinary(payload, pos, length);
            pos += length;
        }
        result["data"] = substrBinary(payload, pos);
        return result;
    }
}
AbstractSymmetricCrypt.METHOD_SIZE = 2;

class DecryptError extends AdscoreError {
}

class OpenSSL extends AbstractSymmetricCrypt {
    constructor(method = "aes-256-cbc", algo = "sha256") {
        super();
        this.method = "aes-256-cbc";
        this.algo = "sha256";
        this.options = 0;
        this.ivLengths = {
            ["aes-128-cbc"]: 16,
            ["aes-192-cbc"]: 16,
            ["aes-256-cbc"]: 16,
            ["aes-128-gcm"]: 12,
            ["aes-192-gcm"]: 12,
            ["aes-256-gcm"]: 12,
        };
        const validMethods = [
            "aes-128-cbc",
            "aes-192-cbc",
            "aes-256-cbc",
            "aes-128-gcm",
            "aes-192-gcm",
            "aes-256-gcm",
        ];
        if (!validMethods.includes(method)) {
            throw new InvalidArgumentError(`Invalid cipher method "${method}"`);
        }
        this.method = method;
        const validAlgorithms = ["sha256", "sha512"];
        if (!validAlgorithms.includes(algo)) {
            throw new InvalidArgumentError(`Invalid hash method "${algo}"`);
        }
        this.algo = algo;
    }
    async key(password, salt) {
        throw new Error("Not supported");
    }
    getIvLength() {
        switch (this.method) {
            case "aes-128-cbc":
            case "aes-192-cbc":
            case "aes-256-cbc":
                return 16;
            case "aes-128-gcm":
            case "aes-192-gcm":
            case "aes-256-gcm":
                return 12;
            default:
                throw new InvalidArgumentError(`Unsupported method "${this.method}"`);
        }
    }
    encryptWithKey(data, key) {
        throw new Error("Not supported");
    }
    decryptWithKey(payload, key) {
        const { method, iv, data } = this.parse(payload, {
            iv: this.ivLengths[this.method],
        });
        if (method !== OpenSSL.METHOD) {
            throw new DecryptError("Unrecognized payload");
        }
        return this.decode(data ?? new Uint8Array(), this.method, key, iv);
    }
    async decode(encryptedData, method, key, iv, tag) {
        const tagLength = tag?.length ?? 0;
        const algorithmName = method
            .replace("-128", "")
            .replace("-192", "")
            .replace("-256", "");
        const algorithm = {
            name: algorithmName,
            iv,
            tagLength: tagLength * 8,
        };
        const enc = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey("raw", typeof key === "string" ? enc.encode(key) : key, algorithm, false, ["decrypt"]);
        const combinedData = new Uint8Array(encryptedData.length + tagLength);
        combinedData.set(encryptedData, 0);
        // in original lib, `crypto` has native `.setAuthTag(tag)` which `crypto.subtle` lacks
        if (!!tag && tagLength > 0) {
            combinedData.set(tag, encryptedData.length); // Append the authTag to the end
        }
        const decryptedBuffer = await crypto.subtle.decrypt(algorithm, cryptoKey, combinedData);
        return new Uint8Array(decryptedBuffer);
    }
}
OpenSSL.METHOD = 0x0200;

/**
 * OpenSSL-based symmetric cryptography
 *
 */
class OpenSSLAEAD extends OpenSSL {
    constructor() {
        super("aes-256-gcm");
        this.tagLength = 16;
    }
    /**
     * Decrypt using key
     *
     * @param string payload       Content to decrypt
     * @param string key           Decryption key
     * @param string aad           Additional authentication data
     * @return string               Decrypted payload
     * @throws DecryptError
     */
    async decryptWithKey(payload, key, aad = "") {
        const { method: method, iv: iv, tag: tag, data: data, } = this.parse(payload, {
            iv: this.ivLengths[this.method],
            tag: this.tagLength,
        });
        if (method !== OpenSSLAEAD.METHOD) {
            throw new DecryptError("Unrecognized payload");
        }
        return this.decode(data ?? new Uint8Array(), this.method, key, iv, tag);
    }
}
OpenSSLAEAD.METHOD = 0x0201;

const decoder = new TextDecoder();
function uInt8ArrayToString(input, type = "chars") {
    const isUIntArray = input instanceof Uint8Array;
    if (!isUIntArray) {
        return input?.toString();
    }
    switch (type) {
        case "chars":
            return decoder.decode(input);
        case "hex":
            let result = "";
            input.forEach((val) => (result += val.toString(16).padStart(2, "0")));
            return result;
    }
    throw new Error("Unsupported type: " + type);
}

class CryptFactory {
    /**
     * Returns Crypt instance
     * @param string $name
     * @return OpenSSL
     */
    static create(name) {
        const nameAsString = typeof name === "string" ? name : uInt8ArrayToString(name);
        switch (nameAsString) {
            case uInt8ArrayToString(pack("v", OpenSSL.METHOD)):
            case "OpenSSL":
            case "openssl":
                return new OpenSSL();
            case uInt8ArrayToString(pack("v", OpenSSLAEAD.METHOD)):
            case "OpenSSLAEAD":
            case "opensslaead":
                return new OpenSSLAEAD();
            default:
                throw new InvalidArgumentError("Unsupported crypt class");
        }
    }
    /**
     * Returns Crypt instance based on payload header
     * @param string $payload
     * @return OpenSSL
     */
    static createFromPayload(payload) {
        const header = substrBinary(payload, 0, 2);
        return CryptFactory.create(header);
    }
    /**
     * Returns Crypt instance based on algorithm/library combination ID
     * @param int $code
     * @return object
     */
    static createFromId(code) {
        const name = pack("v", code);
        return CryptFactory.create(name);
    }
}

class AbstractAsymmetricCrypt {
    /**
     * Expands compacted data to PEM format
     * @param {string} data compacted key data
     * @param {number} lineLength line length for PEM encoding (default 64)
     * @returns {string} PEM formatted key
     */
    static expandPem(data, lineLength = 64) {
        throw new Error("Not supported");
    }
    /**
     * Builds PEM format from key data
     * @param {string} data key data
     * @param {string} label key label
     * @param {number} lineLength line length for PEM encoding (default 64)
     * @returns {string} PEM formatted key
     */
    static encodePem(data, label, lineLength = 64) {
        throw new Error("Not supported");
    }
}

const UINT32_READ_BUFFER = new Uint8Array(4);
/**
 * Partial signature library
 * From: https://www.npmjs.com/package/@litert/signatures
 * Apache 2.0 License: https://github.com/litert/signatures.js?tab=Apache-2.0-1-ov-file#readme
 */
function derToP1363(der) {
    let ctx = [0, 0];
    let [, offset] = derReadLength(der, 1);
    ctx = derReadLength(der, ++offset);
    offset = ctx[1];
    const r = removePrependZero(der.slice(offset, offset + ctx[0]));
    offset += ctx[0];
    ctx = derReadLength(der, ++offset);
    offset = ctx[1];
    const s = removePrependZero(der.slice(offset, offset + ctx[0]));
    if (s.length > r.length) {
        return contactUint8Array([new Uint8Array(s.length - r.length), r, s]);
    }
    else if (r.length > s.length) {
        return contactUint8Array([r, new Uint8Array(r.length - s.length), s]);
    }
    return contactUint8Array([r, s]);
}
function derReadLength(input, offset) {
    let length = input[offset++];
    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (length > 0x7f) {
        const llen = length & 0x7f;
        UINT32_READ_BUFFER.fill(0);
        const source = substrBinary(input, offset, offset + llen);
        const targetStart = 4 - llen;
        UINT32_READ_BUFFER.set(substrBinary(source, 0, 4 - targetStart), targetStart);
        length = new ByteOperations(UINT32_READ_BUFFER).readUInt32BE(0);
        offset += llen;
    }
    return [length, offset];
}
function removePrependZero(bf) {
    let i = 0;
    for (; i < bf.length && !bf[i]; i++)
        ;
    if (i === bf.length) {
        return bf.slice(0, 1);
    }
    return bf.slice(i);
}

function convertInternalHashNameIntoWebCryptos(algo) {
    let hash = "SHA-256";
    switch (algo.toLowerCase()) {
        case "sha256":
        case "sha-256":
            hash = "SHA-256";
            break;
        case "sha512":
        case "sha-512":
            hash = "SHA-512";
            break;
        default:
            throw new Error("Unsupported HASH algorithm");
    }
    return hash;
}

function getHashes() {
    return ["SHA-256", "SHA-384", "SHA-512"];
}
class AsymmetricOpenSSL extends AbstractAsymmetricCrypt {
    constructor(algo = "sha256") {
        super();
        this.algo = "sha256";
        this.options = 1; // Placeholder for OPENSSL_RAW_DATA
        const convertedAlgo = convertInternalHashNameIntoWebCryptos(algo);
        if (!getHashes().includes(convertedAlgo)) {
            throw new InvalidArgumentError(`Invalid hash method "${algo}"`);
        }
        this.algo = convertedAlgo;
    }
    /**
     * Verify signature
     * @param data The string of data used to generate the signature previously
     * @param signature A raw binary string
     * @param publicKey OpenSSL asymmetric key
     * @return boolean
     * @throws VerifyError
     */
    async verify(data, signature, publicKey) {
        const binaryData = new TextEncoder().encode(data);
        const algo = {
            name: "ECDSA",
            namedCurve: "P-256",
            hash: "SHA-256",
        };
        const key = await this.importPublicKey(publicKey, algo);
        const isValid = await crypto.subtle.verify(algo, key, derToP1363(signature), binaryData);
        return isValid;
    }
    /**
     * Generate signature
     * @param data The string of data you wish to sign
     * @param privateKey OpenSSL asymmetric key
     * @return string Computed signature
     */
    sign(data, privateKey) {
        throw new Error("Not supported");
    }
    /**
     * Create EC keypair
     * @param curveName Curve name
     * @return Compacted private key
     */
    static createEcPrivateKey(curveName = "prime256v1") {
        throw new Error("Not supported");
    }
    /**
     * Retrieve public key in PEM format from compacted private key
     * @param data Compacted key
     * @return Public key in PEM format
     */
    static getPublicKeyPem(data) {
        throw new Error("Not supported");
    }
    importPublicKey(pem, algo) {
        return crypto.subtle.importKey("spki", pem, algo, false, ["verify"]);
    }
}

/**
 * Definitions for Judge
 */
class Judge {
}
Judge.OK = 0;
Judge.PU = 3;
Judge.PROXY = 6;
Judge.BOT = 9;
Judge.RESULTS = {
    [Judge.OK]: { verdict: "ok", name: "Clean" },
    [Judge.PU]: { verdict: "junk", name: "Potentially unwanted" },
    [Judge.PROXY]: { verdict: "proxy", name: "Proxy" },
    [Judge.BOT]: { verdict: "bot", name: "Bot" },
};

class ParseError extends AdscoreError {
}

/**
 * Abstract Formatter
 */
class AbstractFormatter {
}

function base64Decode(base64Input) {
    let repairedBase64Input = repairBase64(base64Input);
    var binaryString = atob(repairedBase64Input);
    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
function encodeBase64(input) {
    return btoa(String.fromCharCode(...new Uint8Array(input)));
}
/**
 * Replace `-` to `+` and `_` to `/` that atob do not support.
 */
function repairBase64(base64Input) {
    const charMap = {
        "-": "+",
        _: "/",
    };
    let repairedBase64Input = "";
    for (const char of base64Input) {
        if (charMap[char] !== undefined) {
            repairedBase64Input += charMap[char];
        }
        else {
            repairedBase64Input += char;
        }
    }
    return repairedBase64Input?.trim();
}

/**
 * Generic Base64 formatter
 */
class Base64 extends AbstractFormatter {
    /**
     * @param variant Compatible with BASE64_VARIANT_*
     * @param strict Whether to throw exception on decoding errors
     * @throws Error
     */
    constructor(variant = Base64.BASE64_VARIANT_URLSAFE_NO_PADDING, strict = false) {
        super();
        if (![
            Base64.BASE64_VARIANT_ORIGINAL,
            Base64.BASE64_VARIANT_ORIGINAL_NO_PADDING,
            Base64.BASE64_VARIANT_URLSAFE,
            Base64.BASE64_VARIANT_URLSAFE_NO_PADDING,
        ].includes(variant)) {
            throw new InvalidArgumentError("Invalid base64 variant");
        }
        this.variant = variant;
        this.strict = strict;
    }
    /**
     * Encodes a raw binary string with base64
     * @param value
     * @return string
     * @throws Error
     */
    format(value) {
        throw new Error("Not supported");
    }
    /**
     * Decodes a base64-encoded string into raw binary
     * @param value
     * @return string
     * @throws Error When strict mode is enabled, an exception is thrown in case of unrecognized character
     */
    parse(value) {
        let binary = base64Decode(value);
        if (this.strict && !binary) {
            throw new InvalidArgumentError("Not a valid base64-encoded value");
        }
        return binary;
    }
}
Base64.BASE64_VARIANT_ORIGINAL = 1;
Base64.BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;
Base64.BASE64_VARIANT_URLSAFE = 5;
Base64.BASE64_VARIANT_URLSAFE_NO_PADDING = 7;

/**
 * Invalid or outdated signatures
 */
class VerifyError extends AdscoreError {
}

/**
 * Abstract signature
 */
class AbstractSignature {
    constructor() {
        this.payload = null;
        this.result = null;
    }
    /**
     * Retrieve embedded payload
     * @return Payload | null
     */
    getPayload() {
        return this.payload;
    }
    /**
     * Embed new payload
     * @param payload
     * @return void
     */
    setPayload(payload) {
        this.payload = payload;
    }
    /**
     * Returns verification result
     */
    getResult() {
        if (this.result === null) {
            throw new VerifyError("Result unavailable for unverified signature");
        }
        return this.result;
    }
    /**
     * Simplified signature parsing/validation
     * @param signature Signature content
     * @param ipAddresses Array of client's IP addresses
     * @param userAgent Client's User Agent
     * @param cryptKey Signature decoding key
     * @param formatter Optional formatter (if signature content is not a standard Base64)
     * @return AbstractSignature
     */
    static createFromRequest(signature, ipAddresses, userAgent, cryptKey, formatter = null) {
        throw new Error("Not implemented");
    }
    /**
     * Returns default formatter
     * @return AbstractFormatter
     */
    getDefaultFormatter() {
        return new Base64(Base64.BASE64_VARIANT_URLSAFE_NO_PADDING, true);
    }
    bytesCompare(known, user, n) {
        if (known === null || user === null) {
            return false;
        }
        if (known.length < n || user.length < n) {
            return false;
        }
        return this.hashEquals(substrBinary(known, 0, n), substrBinary(user, 0, n));
    }
    hashEquals(known, user) {
        if (known.length !== user.length) {
            return false;
        }
        return known.every((value, index) => value === user[index]);
    }
}

/**
 * Occurs usually when invalid decoder is applied to signature
 */
class VersionError extends AdscoreError {
}

function arrayKeyExists(key, associativeArray) {
    return Object.keys(associativeArray).includes(key?.toString());
}

function sprintf(format, ...params) {
    const parts = format.matchAll(/(%[a-z0-9]+)/g);
    let paramIndex = 0;
    let result = "";
    for (const key of parts) {
        const param = params[paramIndex];
        if (key[0] === "%02x") {
            result += param.toString(16).padStart(2, "0");
        }
        else {
            result += param.toString();
        }
        paramIndex++;
    }
    return result;
}

function empty(input) {
    if (Array.isArray(input)) {
        return input.length === 0;
    }
    if (input === "0")
        return true;
    return !input;
}

async function createHash(algorithm, input) {
    let hash = convertInternalHashNameIntoWebCryptos(algorithm);
    const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
    const arrayBuffer = await crypto.subtle.digest(hash, data);
    return new Uint8Array(arrayBuffer);
}

async function hashEquals(input, compare) {
    try {
        const a = await createHash("sha256", input);
        const b = await createHash("sha256", compare);
        const decoder = new TextDecoder();
        return decoder.decode(a) === decoder.decode(b);
    }
    catch (e) {
        console.error(e);
        return false;
    }
}

var inet_ntop$1 = function inet_ntop(a) {
  //  discuss at: https://locutus.io/php/inet_ntop/
  // original by: Theriault (https://github.com/Theriault)
  //   example 1: inet_ntop('\x7F\x00\x00\x01')
  //   returns 1: '127.0.0.1'
  //   _example 2: inet_ntop('\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
  //   _returns 2: '::1'

  var i = 0;
  var m = '';
  var c = [];

  a += '';
  if (a.length === 4) {
    // IPv4
    return [a.charCodeAt(0), a.charCodeAt(1), a.charCodeAt(2), a.charCodeAt(3)].join('.');
  } else if (a.length === 16) {
    // IPv6
    for (i = 0; i < 16; i++) {
      c.push(((a.charCodeAt(i++) << 8) + a.charCodeAt(i)).toString(16));
    }
    return c.join(':').replace(/((^|:)0(?=:|$))+:?/g, function (t) {
      m = t.length > m.length ? t : m;
      return t;
    }).replace(m || ' ', '::');
  } else {
    // Invalid length
    return false;
  }
};

var inet_pton$1 = function inet_pton(a) {
  //  discuss at: https://locutus.io/php/inet_pton/
  // original by: Theriault (https://github.com/Theriault)
  // improved by: alromh87 and JamieSlome
  //   example 1: inet_pton('::')
  //   returns 1: '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
  //   example 2: inet_pton('127.0.0.1')
  //   returns 2: '\x7F\x00\x00\x01'

  var m = void 0;
  var i = void 0;
  var j = void 0;
  var f = String.fromCharCode;

  // IPv4
  m = a.match(/^(?:\d{1,3}(?:\.|$)){4}/);
  if (m) {
    m = m[0].split('.');
    m = f(m[0], m[1], m[2], m[3]);
    // Return if 4 bytes, otherwise false.
    return m.length === 4 ? m : false;
  }

  // IPv6
  if (a.length > 39) {
    return false;
  }

  m = a.split('::');

  if (m.length > 2) {
    return false;
  } // :: can't be used more than once in IPv6.

  var reHexDigits = /^[\da-f]{1,4}$/i;

  for (j = 0; j < m.length; j++) {
    if (m[j].length === 0) {
      // Skip if empty.
      continue;
    }
    m[j] = m[j].split(':');
    for (i = 0; i < m[j].length; i++) {
      var hextet = m[j][i];
      // check if valid hex string up to 4 chars
      if (!reHexDigits.test(hextet)) {
        return false;
      }

      hextet = parseInt(hextet, 16);

      // Would be NaN if it was blank, return false.
      if (isNaN(hextet)) {
        // Invalid IP.
        return false;
      }
      m[j][i] = f(hextet >> 8, hextet & 0xff);
    }
    m[j] = m[j].join('');
  }

  return m.join('\x00'.repeat(16 - m.reduce(function (tl, m) {
    return tl + m.length;
  }, 0)));
};

var inet_ntop = inet_ntop$1;
var inet_pton = inet_pton$1;

// from https://github.com/wangwenming/ip2long/blob/master/index.js
let multipliers = [0x1000000, 0x10000, 0x100, 1];
function ip2long(ip) {
    if (ip.includes(":")) {
        // IPv6
        return false;
    }
    let longValue = 0;
    ip.split(".").forEach((part, i) => {
        longValue += Number(part) * multipliers[i];
    });
    return longValue;
}
function long2ip(longValue) {
    return multipliers
        .map((multiplier) => {
        return Math.floor((longValue % (multiplier * 0x100)) / multiplier);
    })
        .join(".");
}

async function createHmac(algo, input, secret) {
    let hash = convertInternalHashNameIntoWebCryptos(algo);
    let algorithm = { name: "HMAC", hash };
    let key = await crypto.subtle.importKey("raw", secret, algorithm, false, ["sign", "verify"]);
    let signature = await crypto.subtle.sign(algorithm.name, key, input);
    return new Uint8Array(signature);
}

function isset(value) {
    return value !== null && value !== undefined;
}

function strlen(input) {
    return input?.length ?? 0;
}

/**
 * Signature v4 parser
 */
class Signature4 extends AbstractSignature {
    constructor(payload = null) {
        super();
        this.VERSION = 4;
        this.FIELD_IDS = {
            /* ulong fields */
            0x00: { name: "requestTime", type: "ulong" },
            0x01: { name: "signatureTime", type: "ulong" },
            0x10: { name: "ipv4", type: "ulong" } /* Debug field */,
            /* ushort fields */
            0x40: { name: null, type: "ushort" } /* Reserved for future use */,
            /* uchar fields */
            0x80: { name: "masterSignType", type: "uchar" },
            0x81: { name: "customerSignType", type: "uchar" },
            /* string fields */
            0xc0: { name: "masterToken", type: "string" },
            0xc1: { name: "customerToken", type: "string" },
            0xc2: { name: "masterToken6", type: "string" },
            0xc3: { name: "customerToken6", type: "string" },
            0xc4: { name: "ipv6", type: "string" },
            0xc5: { name: "masterChecksum", type: "string" },
            0xd0: { name: "userAgent", type: "string" } /* Debug field */,
        };
        this.HASH_SHA256 = 1; /* Default HASH: using SHA256 */
        this.SIGN_SHA256 = 2; /* Default SIGN: using SHA256 */
        this.SIMPLE_TYPES = {
            uchar: { unpack: "Cx/Cv", size: 2 },
            ushort: { unpack: "Cx/nv", size: 3 },
            ulong: { unpack: "Cx/Nv", size: 5 },
            string: { unpack: "Cx/nv", size: 3 /* + length(value) */ },
        };
        this.verificationData = null;
        this.payload = payload;
    }
    /**
     * Simplified signature parsing/validation
     * @param string signature
     * @param array ipAddresses
     * @param string userAgent
     * @param string cryptKey
     * @param AbstractFormatter|null formatter
     * @return self
     */
    static async createFromRequest(signature, ipAddresses, userAgent, cryptKey, formatter = null) {
        const obj = new Signature4();
        obj.parse(signature, formatter);
        try {
            await obj.verify(ipAddresses, userAgent, cryptKey);
        }
        catch (e) {
            console.error(e);
        }
        return obj;
    }
    parse(signature, formatter = null) {
        formatter ?? (formatter = this.getDefaultFormatter());
        this.payload = this.parseStructure(signature, formatter);
    }
    getHashBase(result, requestTime, signatureTime, ipAddress, userAgent) {
        return [result, requestTime, signatureTime, ipAddress, userAgent].join("\n");
    }
    signData(data, privateKey, algorithm = "sha256") {
        throw new Error("Not supported");
    }
    async verifyData(data, signature, publicKey, algorithm = "sha256") {
        const crypt = new AsymmetricOpenSSL(algorithm);
        return await crypt.verify(data, signature, publicKey);
    }
    async hashData(data, salt, algorithm = "sha256") {
        const binaryData = new TextEncoder().encode(data);
        return await createHmac(algorithm, binaryData, salt);
    }
    getVerificationData() {
        return this.verificationData;
    }
    /**
     * Verifies signature
     * @param array ipAddresses
     * @param string userAgent
     * @param string cryptKey
     * @param string signRole
     * @param array|null results
     * @return bool
     * @throws VerifyError
     */
    async verify(ipAddresses, userAgent, cryptKey, signRole = "customer", results = null) {
        results ?? (results = Judge.RESULTS);
        if (!isset(this.payload?.[signRole + "Token"])) {
            throw new VerifyError("Invalid sign role");
        }
        const signType = this.payload?.[signRole + "SignType"];
        for (let ipAddress of ipAddresses) {
            /* Detect whether it's IPv4 or IPv6, normalize */
            const longIp = ip2long(ipAddress);
            ipAddress = "";
            let token = new Uint8Array();
            let v = 4;
            if (longIp !== false) {
                ipAddress = long2ip(longIp);
                token = this.payload?.[signRole + "Token"];
            }
            else {
                ipAddress = inet_ntop(inet_pton(ipAddress));
                token = this.payload?.[signRole + "Token6"] ?? null;
                v = 6;
                if (token === null) {
                    continue;
                }
            }
            /* Check all possible results */
            for (let result in results) {
                let meta = results[Number(result)];
                meta = typeof meta === "object" ? meta : {};
                const signatureBase = this.getHashBase(Number(result), this.payload?.["requestTime"], this.payload?.["signatureTime"], ipAddress, userAgent);
                switch (signType) {
                    case this.HASH_SHA256:
                        const xToken = await this.hashData(signatureBase, cryptKey, "sha256");
                        new TextEncoder();
                        if (await hashEquals(xToken, token)) {
                            this.verificationData = {
                                verdict: meta["verdict"] ?? null,
                                result: Number(result),
                                [`ipv${v}.ip`]: ipAddress,
                                embeddedIpV6: this.verifyEmbeddedIpv6(Number(result), cryptKey, userAgent, signRole),
                            };
                            this.result = Number(result);
                            return true;
                        }
                        break;
                    case this.SIGN_SHA256:
                        const xValid = await this.verifyData(signatureBase, token, cryptKey, "sha256");
                        if (xValid) {
                            this.verificationData = {
                                verdict: meta["verdict"] ?? null,
                                result: Number(result),
                                "ipv{v}.ip": ipAddress,
                                embeddedIpV6: this.verifyEmbeddedIpv6(Number(result), cryptKey, userAgent, signRole),
                            };
                            this.result = Number(result);
                            return true;
                        }
                        break;
                    default:
                        throw new VerifyError("Unrecognized sign type: " + uInt8ArrayToString(signType));
                }
            }
        }
        throw new VerifyError("No verdict matched", 10);
    }
    /**
     * Allows to transport IPv6 over sessions
     * @param int result
     * @param string key
     * @param string userAgent
     * @param string signRole
     * @return string|null
     */
    async verifyEmbeddedIpv6(result, key, userAgent, signRole) {
        if (!isset(this.payload?.["ipV6"]) ||
            empty(this.payload?.["ipV6"]) ||
            !isset(this.payload?.[signRole + "TokenV6"]) ||
            empty(this.payload?.[signRole + "TokenV6"]) ||
            !isset(this.payload?.[signRole + "Checksum"]) ||
            !isset(this.payload?.[signRole + "SignType"])) {
            return null;
        }
        const checksum = await this.hashData(this.payload?.[signRole + "Token"] + this.payload?.[signRole + "TokenV6"], key, "haval128,4");
        if (!(await hashEquals(checksum, this.payload?.[signRole + "Checksum"]))) {
            return null;
        }
        const ipAddress = inet_ntop(this.payload?.["ipV6"]);
        if (empty(ipAddress)) {
            return null;
        }
        const signType = this.payload?.[signRole + "SignType"];
        const signatureBase = this.getHashBase(result, this.payload?.["requestTime"], this.payload?.["signatureTime"], ipAddress, userAgent);
        switch (signType) {
            case this.HASH_SHA256:
                const xToken = await this.hashData(signatureBase, key, "sha256");
                if (await hashEquals(xToken, this.payload?.[signRole + "TokenV6"])) {
                    return ipAddress;
                }
            /* Customer verification unsupported */
        }
        return null;
    }
    readStructureField(signature, type) {
        if (!isset(this.SIMPLE_TYPES[type])) {
            throw new ParseError('Unsupported variable type "' + type + '"');
        }
        const unpackFmtStr = this.SIMPLE_TYPES[type]["unpack"];
        const fieldSize = this.SIMPLE_TYPES[type]["size"];
        switch (type) {
            case "uchar":
            case "ushort":
            case "ulong":
                const v = unpack(unpackFmtStr, signature)["v"] ?? null;
                if (v === null) {
                    throw new ParseError("Premature end of signature");
                }
                return {
                    result: v,
                    signatureSubarray: substrBinary(signature, fieldSize),
                };
            case "string":
                let length = unpack(unpackFmtStr, signature)["v"] ?? null;
                if (length === null) {
                    throw new ParseError("Premature end of signature");
                }
                if (Number(length) & 0x8000) {
                    /* For future use */
                    length = Number(length) & 0xff;
                }
                const v2 = substrBinary(signature, fieldSize, Number(length));
                if (strlen(v2) !== length) {
                    throw new ParseError("Premature end of signature");
                }
                return {
                    result: v2,
                    signatureSubarray: substrBinary(signature, fieldSize + length),
                };
            default:
                throw new ParseError('Unsupported variable type "' + type + '"');
        }
    }
    /**
     * Decodes physical layer of signature
     * @param string input
     * @return array
     * @throws ParseError
     * @throws VersionError
     */
    parseStructure(input, formatter) {
        let signature = formatter.parse(input);
        if (!signature?.length) {
            throw new ParseError("Not a valid base64 signature payload");
        }
        const data = unpack("Cversion/CfieldNum", signature);
        if (data["version"] !== this.VERSION) {
            throw new VersionError(`Signature version not supported`);
        }
        else {
            signature = substrBinary(signature, 2);
        }
        for (let i = 0; i < Number(data.fieldNum); i++) {
            const fieldId = Number(unpack("CfieldId", signature)["fieldId"]) ?? null;
            if (fieldId === null) {
                throw new ParseError("Premature end of signature");
            }
            let fieldTypeDef = { name: null, type: null };
            if (!arrayKeyExists(fieldId, this.FIELD_IDS)) {
                /* Determine field name and size */
                const t = this.FIELD_IDS[fieldId & 0xc0]["type"];
                fieldTypeDef = {
                    /* Guess field size, but leave unrecognized */ type: t,
                    name: sprintf("%s%02x", t, i),
                };
            }
            else {
                fieldTypeDef = this.FIELD_IDS[fieldId];
            }
            if (fieldTypeDef.name === null || fieldTypeDef.type === null) {
                throw new ParseError("Invalid Field ID", new AdscoreError("fieldTypeDef name or type is null"));
            }
            const { result, signatureSubarray } = this.readStructureField(signature, fieldTypeDef["type"]);
            signature = signatureSubarray;
            data[fieldTypeDef["name"]] = result;
        }
        delete data.fieldNum;
        return data;
    }
}

function strcmp(input1, input2) {
    if (input1 === null || input1 === false) {
        input1 = "";
    }
    if (input2 === null || input2 === false) {
        input2 = "";
    }
    return input1?.toString()?.localeCompare(input2?.toString()) ?? null;
}

function strpos(input, searchFor, offset = 0) {
    return input.indexOf(searchFor, offset);
}

/**
 * Common base for serialization/deserialization methods
 *
 */
class AbstractStruct {
    /**
     * Packs structure into serialized format
     * @param mixed $data
     * @return string
     */
    pack(data) {
        throw new Error('Not supported');
    }
    /**
     * Unpacks structure from serialized format
     * @param string $data
     * @return mixed
     */
    unpack(data) {
        if (strpos(uInt8ArrayToString(data), this.TYPE) !== 0) {
            throw new Error("Unexpected serializer type");
        }
        return substrBinary(data, strlen(this.TYPE));
    }
}

const JsonType = "J";
/**
 * JSON serialization adapter
 */
class Json extends AbstractStruct {
    constructor() {
        super(...arguments);
        this.TYPE = JsonType;
    }
    /**
     * Returns the JSON representation of a value
     * @param mixed $data
     * @return string
     */
    pack(data) {
        throw new Error("Not supported");
    }
    /**
     * Takes a JSON encoded string and converts it into a PHP value
     * @param string $data
     * @return mixed
     */
    unpack(data) {
        const structure = JSON.parse(uInt8ArrayToString(super.unpack(data)));
        return structure;
    }
}

const Rfc3986Type = "H";
/**
 * RFC 3986 serialization adapter
 */
class Rfc3986 extends AbstractStruct {
    constructor() {
        super(...arguments);
        this.TYPE = Rfc3986Type;
    }
    /**
     * Encodes structure as URL-encoded query string
     * @param array $data
     * @return string
     */
    pack(data) {
        throw new Error("Not supported");
    }
    /**
     * Parses string as if it were the query string passed via a URL
     * @param string $data
     * @return array
     */
    unpack(data) {
        const searchParams = new URLSearchParams(uInt8ArrayToString(data));
        const res = Array.from(searchParams.entries()).reduce((curr, prev) => {
            curr[prev[0]] = prev[1];
            return curr;
        }, {});
        return res;
    }
}

class StructFactory {
    /**
     * Return Struct class
     * @param string $name
     * @return AbstractStruct
     */
    static create(name) {
        const nameAsString = typeof name === 'string' ? name : new TextDecoder().decode(name);
        switch (nameAsString) {
            case JsonType:
            case "Json":
            case "json":
                return new Json();
            case Rfc3986Type:
            case "Rfc3986":
            case "rfc3986":
                return new Rfc3986();
            default:
                throw new InvalidArgumentError("Unsupported struct class");
        }
    }
    /**
     * Returns Struct class basing on payload
     * @param string $payload
     * @return AbstractStruct
     */
    static createFromPayload(payload) {
        const header = substrBinary(payload, 0, 1);
        return StructFactory.create(header);
    }
}

/**
 * Malformed or truncated signatures
 */
class SignatureParseError extends AdscoreError {
}

const encoder = new TextEncoder();
function decodeStringToUint8Array(input) {
    return encoder.encode(input);
}

/**
 * Signature v5 envelope/parser
 */
class Signature5 extends AbstractSignature {
    /**
     * Creates a new signature envelope
     */
    constructor(zoneId, payload) {
        super();
        this.VERSION = 5;
        this.HEADER_LENGTH = 11;
        this.zoneId = zoneId;
        this.payload = payload ?? null;
    }
    /**
     * Retrieve zone ID
     * @return int|null
     */
    getZoneId() {
        return this.zoneId;
    }
    /**
     * Embed new zone ID
     * @param int zoneId
     * @return void
     */
    setZoneId(zoneId) {
        this.zoneId = zoneId;
    }
    /**
     * Simplified signature parsing/validation
     * @param string signature
     * @param array ipAddresses
     * @param string userAgent
     * @param Closure|string cryptKey
     * @param AbstractFormatter|null formatter
     * @return self
     */
    static async createFromRequest(signature, ipAddresses, userAgent, cryptKey, formatter = null) {
        const obj = new Signature5();
        await obj.parse(signature, this.toCallback(cryptKey), formatter);
        obj.verify(ipAddresses, userAgent);
        return obj;
    }
    static toCallback(input) {
        if (input instanceof Uint8Array) {
            return (zoneId) => input;
        }
        return input;
    }
    /**
     * Default V5 signature validator
     * @param array result
     * @param array ipAddresses
     * @param string userAgent
     * @throws Error
     */
    verify(ipAddresses, userAgent) {
        let matchingIp = null;
        for (const ipAddress of ipAddresses) {
            const nIpAddress = decodeStringToUint8Array(inet_pton(ipAddress));
            if (
            // ip v4
            (isset(this.payload?.["ipv4.ip"]) &&
                this.payload?.["ipv4.ip"] !== "" &&
                this.bytesCompare(nIpAddress, decodeStringToUint8Array(inet_pton(this.payload?.["ipv4.ip"])), this.payload?.["ipv4.v"] ?? 4)) ||
                // ip v6
                (isset(this.payload?.["ipv6.ip"]) &&
                    this.payload?.["ipv6.ip"] !== "" &&
                    this.bytesCompare(nIpAddress, decodeStringToUint8Array(inet_pton(this.payload?.["ipv6.ip"])), this.payload?.["ipv6.v"] ?? 16))) {
                matchingIp = ipAddress;
                break;
            }
        }
        if (matchingIp === null) {
            throw new VerifyError("Signature IP mismatch");
        }
        if (!isset(this.payload?.["b.ua"])) {
            throw new VerifyError("Signature contains no user agent");
        }
        if (strcmp(this.payload?.["b.ua"], userAgent) !== 0) {
            throw new VerifyError("Signature user agent mismatch");
        }
        this.result = this.payload?.["result"] ?? null;
        return true;
    }
    /**
     * Produce an encrypted signature
     * @param AdScore\Common\Struct\AbstractStruct struct
     * @param AdScore\Common\Crypt\Symmetric\AbstractSymmetricCrypt crypt
     * @param string cryptKey
     * @param AdScore\Common\Formatter\AbstractFormatter formatter		Signature formatter
     * @return string
     */
    format(struct, crypt, cryptKey, formatter = null) {
        throw new Error("Not supported");
    }
    /**
     * Parses and decodes a signature
     * @param string signature Formatted signature
     * @param Closure onCryptKeyRequest Zone ID is passed as parameter, this callback should return a decryption key
     * @param AdScore\Common\Formatter\AbstractFormatter formatter Signature format decoder
     */
    async parse(signature, onCryptKeyRequest, formatter = null) {
        formatter ?? (formatter = this.getDefaultFormatter());
        const payload = formatter?.parse(signature);
        if (payload.length <= this.HEADER_LENGTH) {
            throw new SignatureParseError("Malformed signature");
        }
        const { version, length, zone_id } = unpack("Cversion/nlength/Jzone_id", new Uint8Array(payload ?? []));
        if (version !== this.VERSION) {
            throw new SignatureParseError("Invalid signature version");
        }
        const encryptedPayload = substrBinary(payload, this.HEADER_LENGTH, Number(length));
        if (encryptedPayload.length < Number(length)) {
            throw new SignatureParseError("Truncated signature payload");
        }
        this.payload = (await this.decryptPayload(encryptedPayload, onCryptKeyRequest(zone_id)));
        this.zoneId = zone_id;
    }
    /**
     * Decrypts and unpacks payload
     * @param string payload
     * @param string key
     * @return array
     */
    async decryptPayload(payload, key) {
        const crypt = CryptFactory.createFromPayload(payload);
        const decryptedPayload = await crypt.decryptWithKey(payload, key);
        const struct = StructFactory.createFromPayload(decryptedPayload);
        const unpackedPayload = struct.unpack(decryptedPayload);
        if (typeof unpackedPayload !== "object") {
            throw new SignatureParseError("Unexpected payload type " + typeof unpackedPayload);
        }
        this.structType = struct.constructor.name;
        this.encryptionType = crypt.constructor.name;
        return unpackedPayload;
    }
}

function removeHeadersFromKey(key) {
    // get the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    if (!key.includes(pemHeader) && !key.includes(pemFooter)) {
        return key;
    }
    let pemContents = key.substring(pemHeader.length, key.length - pemFooter.length - 1);
    // remove line endings
    pemContents = pemContents.replace(/\n|\r/g, "");
    return pemContents;
}


/**
 * Response templates
 */
class AdscoreResource {
    static screeningPage(signedRequest) {
        return new Response(`<html><body><script src="//c.adsco.re" type="text/javascript"></script>
  <script type="text/javascript">
    function sendData(url, data, callback) {
      var xhr;
      if (window.XMLHttpRequest)
        xhr = new XMLHttpRequest();
      else
        xhr = new ActiveXObject("Microsoft.XMLHTTP");
        xhr.open('POST', url, true);
        xhr.withCredentials = true;
        var xhrol = function(e) {
          if (callback)
            if (xhr.readyState != 4)
                callback(null, 2);
            else if (xhr.status != 200)
              callback(xhr.responseText, 1, xhr.status);
            else
              callback(xhr.responseText, 0);
        }
        if ('onerror' in xhr)
            xhr.onerror = function() {
              if (callback) callback(null, 1)
            }
        if ('onload' in xhr)
            xhr.onload = xhrol;
        else if ('onreadystatechange' in xhr)
            xhr.onreadystatechange = xhrol;
        xhr.send(data);
    }

    function setCookie(cname, cvalue) {
      var d = new Date();
      d.setTime(d.getTime() + (6*60*60*1000));
      var expires = "expires="+ d.toUTCString();
      document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
    }

    if (typeof AdscoreInit !== "function")
      alert('Please disable Adblock to access this page.');
    else if (!navigator.cookieEnabled)
      alert('This website require cookies.');
    else
      AdscoreInit("` +
            ADSCORE_ZONE_API_KEY +
            `", {
          request_signature: ${signedRequest ? `"${signedRequest}"` : "undefined"},
          callback: function(result) {
          if (result.signature == '') {
            if(result.status === "error"){
              alert('Error from Adscore: ' + result.message);
            } else {
              alert('Please disable Adblock to access this page.');
            }
          }
          else
            sendData(document.location.href, result.signature, function(data, status, httpCode) {
              if (status == 2)
                return true;
              /* TODO: Handling 403 errors caused by immediate signature validation */
              if ((status == 1) || (data == '')) {
                alert('Cannot connect to Adscore service. Status: ' + status + ", HTTP Code: " + httpCode + ", Data: " + data);
                return false;
              }
              setCookie('` + cookieName + `', data);
              if ((document.cookie.indexOf('` + cookieName + `=') > -1)) {
                sendData("?AdscoreCookieCheck", Date.now(), function(d, s, hc) {
                  if ((s == 0) && (d.localeCompare("OK") == 0))
                    document.location.replace(document.location.href);
                  else {
                    /* TODO: Handle errors caused by not keeping the cookie */
  //                  alert('Your browser has dodgy cookie support (2).');
                  }
                });
              } //else
                //alert('Your browser has dodgy cookie support (1).');
            });
        }
      });
  </script></body></html>`, {
            status: 200,
            statusText: "OK",
            headers: {
                "Content-Type": "text/html",
                Link: "<//c.adsco.re>;rel=prefetch,<//adsco.re>;rel=preconnect,<//6.adsco.re>;rel=prefetch",
                "Cache-Control": "no-cache, no-store, must-revalidate, no-transform",
                Pragma: "no-cache",
                Expires: "0",
            },
        });
    }
    static refreshPage(signature) {
        var d = new Date();
        d.setTime(d.getTime() + 6 * 60 * 60 * 1000);
        var expires = "Expires=" + d.toUTCString();
        return new Response(signature, {
            status: 200,
            statusText: "OK",
            headers: {
                "Content-Type": "text/html",
                "Set-Cookie": cookieName + "=" +
                    encodeURIComponent(signature) +
                    "; " +
                    expires +
                    "; Path=/;",
                "Cache-Control": "no-cache, no-store, must-revalidate, no-transform",
                Pragma: "no-cache",
                Expires: "0",
            },
        });
    }
    static blockPage(htmlOutput, errorMessage) {
        if (htmlOutput)
            return new Response(errorMessage ||
                `<html><body>Access blocked by <a href="https://www.adscore.com">Adscore</a>, because we believe you might not be a human visitor or you are connecting via proxy or VPN.</body></html>`, {
                status: 403,
                statusText: "Forbidden",
                headers: {
                    "Content-Type": "text/html",
                },
            });
        else
            return new Response(errorMessage || "", {
                status: 403,
                statusText: "Forbidden",
            });
    }
    static okPage(request) {
        return new Response(`OK`, {
            status: 200,
            statusText: "OK",
            headers: {
                "Content-Type": "text/plain",
                "Cache-Control": "no-cache, no-store, must-revalidate, no-transform",
                Pragma: "no-cache",
                Expires: "0",
            },
        });
    }
    static p3pXmlFull(request) {
        /*
            If you plan to introduce your own p3p xml under /w3c/Full_P3P_Policy.xml, uncomment following lines
          */
        //let response = await fetch(request);
        //return response;
        return new Response(`<?xml version="1.0"?><POLICIES xmlns="http://www.w3.org/2002/01/P3Pv1"><EXPIRY date="Wed, 01 Jan 2020 12:00:00 GMT"/><POLICY name="AdScore" discuri="https://www.adscore.com/privacy-policy.html" xml:lang="en"><ENTITY><DATA-GROUP><DATA ref="#business.name">Tomksoft S.A</DATA><DATA ref="#business.contact-info.online.email">support@adscore.com</DATA><DATA ref="#business.contact-info.online.uri">http://adscore.com</DATA><DATA ref="#business.contact-info.telecom.telephone.number">305-492-7735</DATA><DATA ref="#business.contact-info.postal.organization">Tomksoft S.A.</DATA><DATA ref="#business.contact-info.postal.street">75 meters west of park</DATA><DATA ref="#business.contact-info.postal.city">San Pablo de Heredia</DATA><DATA ref="#business.contact-info.postal.stateprov">Heredia</DATA><DATA ref="#business.contact-info.postal.postalcode">3019</DATA><DATA ref="#business.contact-info.postal.country">Costa Rica</DATA></DATA-GROUP></ENTITY><ACCESS><contact-and-other/></ACCESS><DISPUTES-GROUP><DISPUTES resolution-type="service" service="https://www.adscore.com/support" short-description="General"><LONG-DESCRIPTION></LONG-DESCRIPTION><REMEDIES><correct/></REMEDIES></DISPUTES></DISPUTES-GROUP><STATEMENT><EXTENSION optional="yes"><GROUP-INFO xmlns="http://www.software.ibm.com/P3P/editor/extension-1.0.html" name="Panel information"/></EXTENSION><PURPOSE><admin/><contact/><current/><develop/><pseudo-analysis/><pseudo-decision/><individual-analysis/><individual-decision/><tailoring/><historical/><telemarketing/></PURPOSE><RECIPIENT><ours/></RECIPIENT><RETENTION><business-practices/></RETENTION><DATA-GROUP><DATA ref="#dynamic.clickstream"/><DATA ref="#dynamic.http"/><DATA ref="#dynamic.cookies"><CATEGORIES><navigation/><state/><uniqueid/></CATEGORIES></DATA><DATA ref="#user.name"/><DATA ref="#user.business-info"/><DATA ref="#dynamic.miscdata"><CATEGORIES><online/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><financial/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><computer/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><navigation/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><location/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><state/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><demographic/></CATEGORIES></DATA></DATA-GROUP></STATEMENT><STATEMENT><EXTENSION optional="yes"><GROUP-INFO xmlns="http://www.software.ibm.com/P3P/editor/extension-1.0.html" name="Adserving information"/></EXTENSION><PURPOSE><admin/><current/><develop/><pseudo-analysis/><pseudo-decision/></PURPOSE><RECIPIENT><ours/></RECIPIENT><RETENTION><indefinitely/></RETENTION><DATA-GROUP><DATA ref="#dynamic.clickstream"/><DATA ref="#dynamic.http"/><DATA ref="#dynamic.clientevents"/><DATA ref="#dynamic.cookies"><CATEGORIES><navigation/><state/><uniqueid/></CATEGORIES></DATA><DATA ref="#dynamic.searchtext"/><DATA ref="#dynamic.miscdata"><CATEGORIES><uniqueid/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><state/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><location/></CATEGORIES></DATA><DATA ref="#dynamic.miscdata"><CATEGORIES><demographic/></CATEGORIES></DATA></DATA-GROUP></STATEMENT></POLICY></POLICIES>`, {
            status: 200,
            statusText: "OK",
            headers: {
                "Content-Type": "text/xml",
            },
        });
    }
    static p3pXmlEntry(request) {
        /*
            If you plan to introduce your own p3p xml under /w3c/p3p.xml, uncomment following lines
          */
        //let response = await fetch(request);
        //return response;
        return new Response(`<?xml version="1.0"?><META xmlns="http://www.w3.org/2000/12/p3pv1"><POLICY-REFERENCES><POLICY-REF about="Full_P3P_Policy.xml"><INCLUDE>\*</INCLUDE><COOKIE-INCLUDE name="*" value="*" domain="*" path="*"/></POLICY-REF></POLICY-REFERENCES></META>`, {
            status: 200,
            statusText: "OK",
            headers: {
                "Content-Type": "text/xml",
            },
        });
    }
}

function getCookie(cs, cname) {
    let name = cname + "=";
    let decodedCookie = cs;
    let ca = decodedCookie.split(";");
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == " ") {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function getSignatureVersion(payload) {
    const data = unpack("Cversion/CfieldNum", base64Decode(payload));
    return data?.["version"];
}

async function signRequest(requestKey, ipAddress, userAgent) {
    const invalidRequestKey = requestKey.length === 0 ||
        requestKey.indexOf(`<request_key>`) === 0;
    if (invalidRequestKey) {
        return undefined;
    }
    const secret = base64Decode(requestKey);
    const encoder = new TextEncoder();
    const body = [ipAddress, userAgent].join("\n");
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    const key = await crypto.subtle.importKey("raw", secret, algorithm, false, [
        "sign",
        "verify",
    ]);
    const signature = await crypto.subtle.sign(algorithm.name, key, encoder.encode(body));
    const digest = encodeBase64(signature);
    return digest;
}

const cookieName = "VerifiedByAdscore_" + ADSCORE_ZONE_API_KEY;
var webWorker = {
    async fetch(request, env, ctx) {
        const ipAddress = [
            request.headers.get("cf-connecting-ip"),
            request.headers.get("X-Forwarded-For"),
        ].filter((x) => !!x);
        const isInCloudflareWebEditor = (request.headers.get("cf-ew-preview-server")?.length ?? 0) > 0;
        // Cloudflare Web Editor is hiding real IP (Adscore sees real one). Signature will
        // throw an error, so OK page is displayed in this case.
        if (isInCloudflareWebEditor) {
            console.log("Cloudflare editor detected, skipping to OK page");
            return AdscoreResource.okPage(request);
        }
        const userAgent = request.headers.get("User-Agent");
        const cookie = request.headers.get("Cookie");
        const signedRequest = await signRequest(ADSCORE_ZONE_REQUEST_KEY, ipAddress?.[0] ?? "", userAgent ?? "");
        let isHtmlRequest = true; // request.headers.get('Accept').includes('text/html');
        let signature;
        const requestUrl = new URL(request.url);
        if (requestUrl.pathname.endsWith("/w3c/p3p.xml")) {
            return AdscoreResource.p3pXmlEntry(request);
        }
        else if (requestUrl.pathname.endsWith("/w3c/Full_P3P_Policy.xml")) {
            return AdscoreResource.p3pXmlFull(request);
        }
        else if (requestUrl.search.localeCompare("?AdscoreCookieCheck") == 0) {
            isHtmlRequest = false;
        }
        /* If we have signature cookie, we can decode it and decide what to do */
        if (cookie !== null) {
            signature = decodeURIComponent(getCookie(cookie, cookieName));
            if (signature && signature != "") {
                try {
                    const verdict = await getVerdict(signature, ipAddress, userAgent);
                    if (requestUrl.search.localeCompare("?AdscoreCookieCheck") == 0) {
                        return AdscoreResource.okPage(request);
                    }
                    else if (ALLOWED_VERDICTS.indexOf(verdict) > -1) {
                        let response = await fetch(request);
                        return response;
                    }
                    else {
                        return AdscoreResource.blockPage(isHtmlRequest);
                    }
                }
                catch (err) {
                    /* If signature is imparseable, let it generate a new one, so don't exit */
                }
            }
        }
        /* Cookie check - reject */
        if (requestUrl.search.localeCompare("?" + cookieName) == 0) {
            return AdscoreResource.blockPage(false);
        }
        /* We don't have cookie with signature to validate, let's check POST body */
        if (request.method == "POST") {
            signature = await request.text();
            if (signature != "") {
                try {
                    await getVerdict(signature, ipAddress, userAgent);
                    return AdscoreResource.refreshPage(signature);
                }
                catch (err) {
                    return AdscoreResource.blockPage(isHtmlRequest, err?.toString());
                }
            }
        }
        return isHtmlRequest
            ? AdscoreResource.screeningPage(signedRequest)
            : AdscoreResource.blockPage(isHtmlRequest);
    },
};
async function getVerdict(signature, ipAddress, userAgent) {
    let result = null;
    try {
        const version = getSignatureVersion(signature);
        switch (version) {
            case 4:
                result = await Signature4.createFromRequest(signature, ipAddress, userAgent, base64Decode(removeHeadersFromKey(ADSCORE_ZONE_RESPONSE_KEY)));
                break;
            case 5:
                result = await Signature5.createFromRequest(signature, ipAddress, userAgent, base64Decode(removeHeadersFromKey(ADSCORE_ZONE_RESPONSE_KEY)));
                break;
            default:
                throw new Error("Unsupported signature version");
        }
    }
    catch (e) {
        console.error(e);
    }
    const verdict = Judge.RESULTS[result?.getResult() ?? -1]?.verdict ?? -1;
    return verdict;
}

export { cookieName, webWorker as default };
