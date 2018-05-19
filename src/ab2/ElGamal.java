package ab2;

import java.math.BigInteger;

/**
 * Interface für die Verwendung des ElGamal-Kryptosystems.
 *
 * @author Raphael Wigoutschnigg
 */
public interface ElGamal {

	/**
	 * Definiert die Bitlänge der Schlüssekomponenten
	 *
	 * @param n
	 */
	public void init(int n);

	/**
	 * Liefert den öffentlichen Schlüssel
	 *
	 * @return
	 */
	public PublicKey getPublicKey();

	/**
	 * Liefert den geheimen Schlüssel
	 *
	 * @return
	 */
	public PrivateKey getPrivateKey();

	/**
	 * Verschlüsselt die Daten.
	 *
	 * @param data
	 * @return
	 */
	public byte[] encrypt(byte[] data);

	/**
	 * Entschlüsselt die Daten. Ob das OAEP verwendet wird, muss den Daten entnommen
	 * werden
	 *
	 * @param datam
	 * @return
	 */
	public byte[] decrypt(byte[] data);

	/**
	 * Signiert die Daten
	 *
	 * @param message
	 * @return
	 */
	public byte[] sign(byte[] message);

	/**
	 * Verifiziert die Signatur
	 *
	 * @param message
	 * @param signature
	 * @return
	 */
	public Boolean verify(byte[] message, byte[] signature);

	public static class PublicKey {
		private BigInteger p;
		private BigInteger g;
		private BigInteger e;

		public PublicKey(BigInteger p, BigInteger g, BigInteger e) {
			this.p = p;
			this.g = g;
			this.e = e;
		}

		public BigInteger getE() {
			return e;
		}

		public void setE(BigInteger e) {
			this.e = e;
		}

		public BigInteger getG() {
			return g;
		}

		public void setG(BigInteger g) {
			this.g = g;
		}

		public BigInteger getP() {
			return p;
		}

		public void setP(BigInteger p) {
			this.p = p;
		}
	}

	public static class PrivateKey {
		private BigInteger p;
		private BigInteger g;
		private BigInteger d;

		public PrivateKey(BigInteger p, BigInteger g, BigInteger d) {
			this.p = p;
			this.g = g;
			this.d = d;
		}

		public BigInteger getD() {
			return d;
		}

		public void setD(BigInteger d) {
			this.d = d;
		}

		public BigInteger getG() {
			return g;
		}

		public void setG(BigInteger g) {
			this.g = g;
		}

		public BigInteger getP() {
			return p;
		}

		public void setP(BigInteger p) {
			this.p = p;
		}
	}
}