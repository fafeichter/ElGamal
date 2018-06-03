package ab2.impl.FeichterProhinig;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import ab2.ElGamal;

public class ElGamalImpl implements ElGamal {

	/**
	 * helper constants
	 */
	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final int BYTE_SIZE = Byte.SIZE;

	/**
	 * strong random number generator
	 */
	public static final SecureRandom random = new SecureRandom();

	/**
	 * measure uncertainty that a prime number is not really a prime number
	 */
	private static final int CERTAINTY = 10;

	/**
	 * used algorithm to calculate hash codes
	 */
	private static final String HASH_ALGORITHM = "SHA-256";

	/**
	 * padding is used because of the possible different length of decrypted blocks
	 */
	private static final byte[] PADDING = { 0, 0, 0, 0, 0, 0, 1 };
	private static final int PADDING_SIZE = PADDING.length;

	/**
	 * keys
	 */
	private PublicKey publicKey = null;
	private PrivateKey privateKey = null;

	@Override
	public void init(int n) {
		// p = strong prime number
		BigInteger p = getPrimeNumber(n);

		// g = a generator of the cyclic group G = [Z/Z[p]]*
		BigInteger g = getGenerator(p);

		// d = random number in {2, ..., p - 2}
		BigInteger d = getRandomNumberInRange(p.subtract(TWO));

		// e = g ^ a mod p
		BigInteger e = g.modPow(d, p);

		// private key is (p, g, d)
		this.privateKey = new PrivateKey(p, g, d);

		// public key is (p, g, e)
		this.publicKey = new PublicKey(p, g, e);
	}

	@Override
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	@Override
	public byte[] encrypt(byte[] data) {
		BigInteger p = publicKey.getP();
		BigInteger g = publicKey.getG();
		BigInteger e = publicKey.getE();

		// r = another random number in {2, ..., p - 2}
		BigInteger r;
		do {
			r = getRandomNumberInRange(p.subtract(ONE));
		} while (r.gcd(p.subtract(ONE)).compareTo(ONE) != 0);

		// g ^ r mod p first part of cipher
		BigInteger c1 = g.modPow(r, p);
		byte[] c1Arr = c1.toByteArray();

		byte[] c2 = null;

		if (!isEmpty(data)) {
			int originalLength = (int) Math.ceil(p.bitLength() / 2 / (double) BYTE_SIZE);
			int blockLength = originalLength - PADDING_SIZE;
			int cipherBlockLength = p.toByteArray().length;
			int cipherLength = (int) Math.ceil(data.length / (double) blockLength) * cipherBlockLength;

			c2 = new byte[cipherLength];

			int steps = 1;
			do {
				int start = (steps - 1);
				byte[] messagePart = new byte[originalLength];
				int copyLength = data.length - start * blockLength < blockLength ? data.length - start * blockLength : blockLength;

				System.arraycopy(PADDING, 0, messagePart, 0, PADDING_SIZE);
				System.arraycopy(data, start * blockLength, messagePart, PADDING_SIZE, copyLength);

				messagePart = Arrays.copyOfRange(messagePart, 0, copyLength + PADDING_SIZE);
				byte[] cipherBlock = proccessByteBlockEnc(new BigInteger(messagePart), e, r, p).toByteArray();
				System.arraycopy(cipherBlock, 0, c2, start * cipherBlockLength + (cipherBlockLength - cipherBlock.length), cipherBlock.length);

				steps++;
			} while ((steps - 1) * blockLength < data.length);
		}

		byte[] cipher = new byte[c1Arr.length + c2.length + 1];
		cipher[0] = (byte) (132 - c1Arr.length);

		System.arraycopy(c1Arr, 0, cipher, 1, c1Arr.length);
		System.arraycopy(c2, 0, cipher, 1 + c1Arr.length, c2.length);

		return cipher;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		BigInteger p = privateKey.getP();
		BigInteger d = privateKey.getD();

		byte[] original = null;
		int c1len = 132 - data[0];

		byte[] c1Arr = new byte[c1len];
		byte[] cipher = new byte[data.length - c1len - 1];

		System.arraycopy(data, 1, c1Arr, 0, c1len);
		System.arraycopy(data, 1 + c1len, cipher, 0, data.length - c1len - 1);

		BigInteger c1 = new BigInteger(c1Arr);

		if (!isEmpty(cipher)) {
			int originalLength = (int) Math.ceil(p.bitLength() / 2 / (double) BYTE_SIZE);
			int blockLength = originalLength - PADDING_SIZE;
			int dataBlockLength = p.toByteArray().length;
			int messageLength = (int) Math.ceil(cipher.length / (double) dataBlockLength) * blockLength;

			original = new byte[messageLength];

			int steps = 1;
			int pos = 0;
			do {
				int start = steps - 1;
				byte[] dataPart = Arrays.copyOfRange(cipher, start * dataBlockLength, start * dataBlockLength + dataBlockLength);
				byte[] messageBlock = proccessByteBlockDec(c1, new BigInteger(dataPart), d, p).toByteArray();

				if (messageBlock[0] != 1) {
					return new byte[0];
				}

				if (messageBlock.length < original.length) {
					System.arraycopy(messageBlock, 0 + 1, original, pos, messageBlock.length - 1);
				}

				pos += messageBlock.length - 1;
				steps++;
			} while (steps * dataBlockLength <= cipher.length);

			original = Arrays.copyOfRange(original, 0, pos);
		}

		return original;
	}

	@Override
	public byte[] sign(byte[] message) {
		BigInteger p = privateKey.getP();
		BigInteger g = privateKey.getG();
		BigInteger d = privateKey.getD();

		BigInteger s = null;
		BigInteger r = null;

		do {
			// k = random number with 1 < k < p - 1 and gcd(k, p - 1) = 1
			BigInteger k;
			do {
				k = getRandomNumberInRange(p.subtract(ONE));
			} while (k.gcd(p.subtract(ONE)).compareTo(ONE) != 0);

			// r = g^k mod p
			r = g.modPow(k, p);

			// s = (H(m) - d * r) * k^(- 1) mod (p - 1)
			BigInteger hM = new BigInteger(toHash(message));
			s = (hM.subtract(d.multiply(r).mod(p))).multiply(k.modInverse(p)).mod(p.subtract(ONE));
		} while (s.equals(ZERO));

		byte[] rArr = r.toByteArray();
		byte[] sArr = s.toByteArray();

		byte[] sign = new byte[rArr.length + sArr.length + 1];
		sign[0] = (byte) (132 - rArr.length);

		System.arraycopy(rArr, 0, sign, 1, rArr.length);
		System.arraycopy(sArr, 0, sign, 1 + rArr.length, sArr.length);

		return sign;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		BigInteger p = publicKey.getP();
		BigInteger g = publicKey.getG();
		BigInteger e = publicKey.getE();

		int rArrlen = 132 - signature[0];

		byte[] rArr = new byte[rArrlen];
		byte[] sArr = new byte[signature.length - rArrlen - 1];

		System.arraycopy(signature, 1, rArr, 0, rArrlen);
		System.arraycopy(signature, 1 + rArrlen, sArr, 0, signature.length - rArrlen - 1);

		BigInteger r = new BigInteger(rArr);
		BigInteger s = new BigInteger(sArr);

		// preconditions for a valid signature
		if (ZERO.compareTo(r) > -1 || r.compareTo(p) > -1 || ZERO.compareTo(s) > -1 || r.compareTo(p.subtract(ONE)) > -1) {
			return false;
		}

		// g^(H(m)) must be congruent to e^r * r^s mod p
		BigInteger mH = new BigInteger(toHash(message));

		BigInteger gHm = g.modPow(mH, p);
		BigInteger eRrS = (e.modPow(r, p)).multiply(r.modPow(s, p)).mod(p);

		return gHm.equals(eRrS);
	}

	/**
	 * Calculates a strong prime number with the specified numBits. A prime number p
	 * is a strong prime number if it has the form p = 2 * q + 1 with q = prime
	 * number.
	 * 
	 * @param numBits
	 *            number of bits of the prime number to calculate
	 * @return strong prime number
	 */
	private static BigInteger getPrimeNumber(int numBits) {
		if (numBits < 2) {
			throw new ArithmeticException("bitLength < 2");
		}

		BigInteger p = null;

		BigInteger q = null;
		do {
			// q = prime number
			q = BigInteger.probablePrime(numBits - 1, random);
			// p = 2 * q + 1
			p = q.multiply(TWO).add(BigInteger.ONE);
		} while (!p.isProbablePrime(CERTAINTY) || !q.multiply(TWO).add(ONE).equals(p) || p.bitLength() != numBits);

		return p;
	}

	/**
	 * Calculates a random number in {0, n - 1}
	 * 
	 * @param n
	 *            end of the range
	 * @return random number in {0, n - 1}
	 */
	private static BigInteger getRandomNumberInRange(BigInteger n) {
		if (n == null || n.compareTo(ZERO) == -1) {
			throw new IllegalArgumentException("n must be greater than or equal to zero");
		}

		return new BigInteger(n.bitLength() / 2, random);
	}

	/**
	 * Calculates a generator of the group G = [Z/Z[p]]*. a is a generator of the
	 * group G if p = strong prime number and a in {2, ..., p-2} and a ^ ((p - 1) /
	 * 2) mod p != 1
	 * 
	 * @param p
	 *            strong prime number
	 * @return generator of the group G = [Z/Z[p]]*
	 */
	private static BigInteger getGenerator(BigInteger p) {
		if (p == null) {
			throw new IllegalArgumentException("p may not be null");
		}

		BigInteger a = null;
		do {
			a = getRandomNumberInRange(p.subtract(BigInteger.ONE));
		} while (a.modPow((p.subtract(ONE)).divide(TWO), p).equals(ONE));

		return a;
	}

	/**
	 * Returns true if the specified array is empty, otherwise false.
	 * 
	 * @param arr
	 *            Array
	 * 
	 * @return true if the specified array is empty, otherwise false
	 */
	private static boolean isEmpty(byte[] arr) {
		return arr == null || arr.length == 0;
	}

	private static BigInteger proccessByteBlockEnc(BigInteger m, BigInteger e, BigInteger r, BigInteger p) {
		return m.multiply(e.modPow(r, p)).mod(p);
	}

	private static BigInteger proccessByteBlockDec(BigInteger c1, BigInteger c2, BigInteger d, BigInteger p) {
		// inverse secret key
		BigInteger dec = c1.modPow(d, p);
		BigInteger dInv = dec.modInverse(p);

		return dInv.multiply(c2).mod(p);
	}

	/**
	 * Returns a hash code value for the specified data array.
	 * 
	 * @param data
	 *            array of bytes to calculate the hash for
	 * @return hash code value for the specified data as array of bytes
	 */
	private static byte[] toHash(byte[] data) {
		byte[] hash = null;

		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
			hash = digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return hash;
	}
}