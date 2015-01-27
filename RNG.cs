using System;
using System.Security.Cryptography;

namespace AdiIRC_Encrypt {
	public class RNG {
		private static RandomNumberGenerator _rng;
		private static RandomNumberGenerator rng {
			get {
				if (_rng == null) {
					_rng = RandomNumberGenerator.Create();
				}
				return _rng;
			}
		}
		
		public static byte[] GetBytes(int count = 32) {
			byte[] result = new byte[count];
			rng.GetBytes(result);
			return result;
		}
	}
}
