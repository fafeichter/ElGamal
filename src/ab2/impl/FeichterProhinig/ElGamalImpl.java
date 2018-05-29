package ab2.impl.FeichterProhinig;

import java.math.BigInteger;
import java.security.SecureRandom;

import ab2.ElGamal;

public class ElGamalImpl implements ElGamal {

	/**
	 * helper constants
	 */
	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);

	/**
	 * strong random number generator
	 */
	public static final SecureRandom random = new SecureRandom();

	/**
	 * measure uncertainty that a prime number is not really a prime number
	 */
	private static final int CERTAINTY = 10;

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
		BigInteger d = getRandomNumberInRange(p.subtract(BigInteger.ONE));

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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] sign(byte[] message) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		// TODO Auto-generated method stub
		return null;
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
}