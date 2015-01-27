using System;
using AdiIRCAPI;
using Chaos.NaCl;

namespace System.Runtime.CompilerServices {
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class
	| AttributeTargets.Method)]
	public sealed class ExtensionAttribute : Attribute { }
}

namespace AdiIRC_Encrypt {
	public static class Extensions {
//		public static bool SendPrivMessage(this IServer server, string target, string msg) {
//			return server.SendRaw(string.Format("PRIVMSG {0} :{1}", target, msg));
//		}
		public static bool SendFakePrivMessage(this IServer server, IUser source, string msg) {
			string line = string.Format(":{0}!{1}@{2} PRIVMSG {3} :{4}", source.Nick, source.Ident, source.Host, server.UserNick, msg);
			return server.SendFakeRaw(line);
		}

		public static byte[] SubArray(this byte[] data, int startIdx, int length = -1) {
			if (length == -1) {
				length = data.Length - startIdx;
			}
			byte[] result = new byte[length];
			Array.Copy(data, startIdx, result, 0, length);
			return result;
		}

		public static string ToBase64String(this byte[] data) {
			return CryptoBytes.ToBase64String(data);
		}
		public static byte[] ReadBase64(this string data) {
			return CryptoBytes.FromBase64String(data);
		}
	}
}
