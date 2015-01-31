using System;
using AdiIRCAPI;
using Chaos.NaCl;

namespace AdiIRC_Encrypt {
	public class PMKey : IDisposable {
		private string user;
		private byte[] myPrivKey;
		public byte[] MyPublicKey {
			get {
				return MontgomeryCurve25519.GetPublicKey(myPrivKey);
			}
		}
		private byte[] usersPubKey;
		public byte[] UsersPubKey {
			get { return usersPubKey; }
		}
		private byte[] sharedKey;
		public byte[] SharedKey {
			get { return sharedKey; }
		}
		
		public PMKey(string forUser) {
			user = forUser;
			myPrivKey = RNG.GetBytes(32);
		}
		public void SetUsersPublicKey(byte[] pubKey) {
			usersPubKey = pubKey;
			sharedKey = MontgomeryCurve25519.KeyExchange(usersPubKey, myPrivKey);
			MontgomeryCurve25519.KeyExchangeOutputHashNaCl(sharedKey, 0);
		}

		public void Dispose() {
			CryptoBytes.InternalWipe(myPrivKey, 0, myPrivKey.Length);
		}
	}
}
