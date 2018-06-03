package ab2.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.BeforeClass;
import org.junit.Test;

import ab2.ElGamal;
import ab2.ElGamal.PrivateKey;
import ab2.ElGamal.PublicKey;
import ab2.impl.FeichterProhinig.ElGamalImpl;

public class ElGamalTest {

	private static ElGamal elGamal_small = new ElGamalImpl();
	private static ElGamal elGamal = new ElGamalImpl();

	/**
	 * Kleine Schl�ssell�nge, um die Zahlen faktorisieren zu k�nnen. Wird nur beim
	 * Initialisierungstest verwendet
	 */
	private static int KEYLENGTH_SMALL = 56;

	/**
	 * Die Schl�ssell�nge f�r die restlichen Tests. Es wird hier auf jeden Fall mit
	 * Vielfachen von 8 getestet.
	 */
	private static int KEYLENGTH = 1024;

	/**
	 * Gibt an, wie oft die Initialisierung getestet werden soll
	 */
	private static int TESTCOUNT_INIT = 10;

	/**
	 * Gibt an, wie viele kurze Nachrichten verschl�sselt werden
	 */
	private static int TESTCOUNT_ENC_SHORT = 1000;

	/**
	 * Gibt an, wie viele lange Nachrichten verschl�sselt werden
	 */
	private static int TESTCOUNT_ENC_LONG = 50;

	/**
	 * Gibt an, wie viele Nachrichten signiert werden
	 */
	private static int TESTCOUNT_SIGN = 1000;

	/**
	 * Gibt an, wie oft bei jedem Test die Schl�sselkomponenten neu initialisiert
	 * werden. Wenn man den Wert erh�ht, sollte man es nicht eilig haben :)
	 */
	private static int TESTCOUNT_REPEAT = 1;

	@BeforeClass
	public static void initElGamal() {
		System.out.println("Starte Initialisierung des Schl�sselmaterials");
		elGamal.init(KEYLENGTH);
		System.out.println("Initialisierung beendet");
	}

	// 2 Pts
	@Test
	public void testInit_2() {

		for (int i = 0; i < TESTCOUNT_INIT; i++) {
			elGamal_small.init(KEYLENGTH_SMALL);

			PublicKey pub = elGamal_small.getPublicKey();
			PrivateKey priv = elGamal_small.getPrivateKey();

			BigInteger p = pub.getP();

			// Bitl�nge muss passen
			assertEquals(p.bitLength(), KEYLENGTH_SMALL);

			List<Long> factors = primeFactors(p.subtract(BigInteger.ONE).longValue());

			// Es darf nur zwei Faktore geben (2 und q)
			assertEquals(2, factors.size());

			BigInteger g = pub.getG();

			// g darf nicht 1 und nicht p-1 (= -1) sein
			assertNotEquals(BigInteger.ONE, g);
			assertNotEquals(p.subtract(BigInteger.ONE), g);

			// g^q mod p muss entweder p-1 oder 1 sein (beides ist ok). Das Quadrat davon
			// muss somit 1 sein
			BigInteger res = g.modPow(BigInteger.valueOf(factors.get(1)), p).modPow(BigInteger.valueOf(2), p);
			assertEquals(BigInteger.ONE, res.abs());

			// Teste, ob der private und der �ffentliche Teil zusammen passen
			assertNotEquals(BigInteger.ZERO, priv.getD());
			assertNotEquals(BigInteger.ONE, priv.getD());
			assertNotEquals(p.subtract(BigInteger.ONE), priv.getD());
			assertEquals(pub.getE(), priv.getG().modPow(priv.getD(), priv.getP()));
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionShort_2() {

		for (int rep = 0; rep < TESTCOUNT_REPEAT; rep++) {
			// Falls wir h�ufiger als 1x testen, dann elGamal neu initialisieren
			if (rep > 0) {
				initElGamal();
			}

			Random r = new Random(System.currentTimeMillis());
			int dataLength = 4;
			byte[] data = new byte[dataLength];

			for (int i = 0; i < TESTCOUNT_ENC_SHORT; i++) {
				r.nextBytes(data);

				testElGamalEnc(data, r, false);
			}
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionLong_2() {
		for (int rep = 0; rep < TESTCOUNT_REPEAT; rep++) {
			// Falls wir h�ufiger als 1x testen, dann elGamal neu initialisieren
			if (rep > 0) {
				initElGamal();
			}

			Random r = new Random(System.currentTimeMillis());

			for (int i = 0; i < TESTCOUNT_ENC_LONG; i++) {
				int dataLength = KEYLENGTH / 8 * (i + 1) + r.nextInt(128);
				byte[] data = new byte[dataLength];
				r.nextBytes(data);

				testElGamalEnc(data, r, false);
			}
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionCipherSize_2() {
		for (int rep = 0; rep < TESTCOUNT_REPEAT; rep++) {
			// Falls wir h�ufiger als 1x testen, dann elGamal neu initialisieren
			if (rep > 0) {
				initElGamal();
			}

			Random r = new Random(System.currentTimeMillis());

			for (int i = 0; i < TESTCOUNT_ENC_LONG; i++) {
				int dataLength = KEYLENGTH / 8 * (i + 1) + r.nextInt(128);
				byte[] data = new byte[dataLength];
				r.nextBytes(data);

				testElGamalEnc(data, r, true);
			}
		}
	}

	private void testElGamalEnc(byte[] data, Random r, boolean checkSize) {
		// Chiffrate m�ssen unterschiedlich sein
		byte[] cipher1 = elGamal.encrypt(data);
		byte[] cipher2 = elGamal.encrypt(data);
		assertEquals(false, Arrays.equals(cipher1, cipher2));

		// Entschl�sselt muss es wieder das gleiche sein
		byte[] decipher1 = elGamal.decrypt(cipher1);
		byte[] decipher2 = elGamal.decrypt(cipher2);
		assertArrayEquals(decipher1, decipher2);

		if (checkSize) {
			// Inputl�nge ist ein Byte k�rzer als der Schl�ssel (damit ist m<p)
			int optimalInputBlockLength = KEYLENGTH / 8 - 1;
			// Optimal ist ein Chiffratblock genau 2*Schl�ssell�nge
			int optimalCipherBlockLength = KEYLENGTH / 8 * 2;

			// Bestimme die Anzahl der Inputbl�cke
			int numInputBlocks = data.length / optimalInputBlockLength;
			if (data.length % optimalInputBlockLength != 0) {
				numInputBlocks++;
			}

			// Erwartete L�nge des Chiffrats
			int expectedCipherSize = numInputBlocks * optimalCipherBlockLength;
			assertEquals(expectedCipherSize, cipher1.length);
		}

		if (r.nextBoolean()) {
			byte[] message_decrypted = elGamal.decrypt(cipher1);

			assertArrayEquals(data, message_decrypted);

		} else {
			// Baue einen einzigen Bit-Fehler in das Chiffrat ein
			int pos = r.nextInt(cipher1.length);
			cipher1[pos] = (byte) (cipher1[pos] ^ 0x01);

			byte[] message_decrypted = elGamal.decrypt(cipher1);

			assertEquals(false, Arrays.equals(data, message_decrypted));
		}
	}

	// 2 Pts
	@Test
	public void testSignature_2() {
		for (int rep = 0; rep < TESTCOUNT_REPEAT; rep++) {
			// Falls wir h�ufiger als 1x testen, dann elGamal neu initialisieren
			if (rep > 0) {
				initElGamal();
			}

			Random r = new Random(System.currentTimeMillis());

			for (int i = 0; i < TESTCOUNT_SIGN; i++) {
				int dataLength = KEYLENGTH / 8 * i + 1;
				byte[] data = new byte[dataLength];

				r.nextBytes(data);

				byte[] sign = elGamal.sign(data);

				// Da der Randomisierer mitgesendet wird, muss die L�nge der Signatur genau der
				// doppelten Bitl�nge von p entsprechen
				assertEquals(2 * KEYLENGTH / 8, sign.length);

				if (r.nextBoolean()) {
					// Keine �nderung der Signatur/Daten

					assertEquals(true, elGamal.verify(data, sign));
				} else {

					if (r.nextBoolean()) {
						// Baue einen einzigen Bit-Fehler in die Daten ein
						int pos = r.nextInt(data.length);
						data[pos] = (byte) (data[pos] ^ 0x01);
					} else {
						// Baue einen einzigen Bit-Fehler in die Signatur ein
						int pos = r.nextInt(sign.length);
						sign[pos] = (byte) (sign[pos] ^ 0x01);
					}

					assertEquals(false, elGamal.verify(data, sign));
				}
			}
		}
	}

	private static List<Long> primeFactors(long number) {
		List<Long> primefactors = new ArrayList<>();

		long act = number;
		long upperLimit = (long) Math.sqrt(act);

		for (long i = 2; i <= upperLimit; i++) {
			if (number % i == 0) {
				primefactors.add(i);
				primefactors.add(number / i);
			}
		}

		return primefactors;
	}
}