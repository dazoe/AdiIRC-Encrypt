using System;
using System.Collections.Generic;
using System.Text;
using AdiIRCAPI;
using Chaos.NaCl;

namespace System.Runtime.CompilerServices {
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class
	| AttributeTargets.Method)]
	public sealed class ExtensionAttribute : Attribute {
	}
}

namespace AdiIRC_Encrypt {
	public static class Extensions {
		private static char escapeChar = '!';
		//public static bool SendPrivMessage(this IServer server, string target, string msg) {
		//	return server.SendRaw(string.Format("PRIVMSG {0} :{1}", target, msg));
		//}
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

		public static string IrcEncode(this byte[] data) {
			unchecked {
				int dataLen = data.Length;
				int ls = 0; //left shift
				int rs = 7; //right shift
				int r = 0; //carry bits
				StringBuilder encoded = new StringBuilder();
				for (int i = 0; i < dataLen; i++) {
					if (ls > 7) {
						i--;
						ls = 0;
						rs = 7;
					}
					int nc = data[i];
					int r1 = nc;				// save $nc
					nc = nc << ls;				// shift left for $rs
					nc = (nc & 0x7f) | r;		// OR carry bits
					r = (r1 >> rs) & 0x7f;		// shift right and save carry bits
					ls++;
					rs--;
					if ((nc == 0) || (nc == 1) || (nc == '\n') || (nc == '\r') || (nc == escapeChar)) { //escaping
						nc = nc + escapeChar;
						encoded.Append(escapeChar);
					}
					encoded.Append((char)nc);
				}
				//add the carry....
				if ((r == 0) || (r == 1)|| (r == '\n') || (r == '\r') || (r == escapeChar)) { //escaping
					r = r + escapeChar;
					encoded.Append(escapeChar);
				}
				encoded.Append((char)r);
				return encoded.ToString();
			}			
		}
		public static byte[] IrcDecode(this string str) {
			unchecked {
				int strLen = str.Length;
				int rs = 8;
				int ls = 7;
				int r = 0;
				List<byte> result = new List<byte>(str.Length);
				for (int i = 0; i < strLen; i++) {
					int nc = str[i];
					if (nc == escapeChar) {
						i++;
						nc = str[i] - escapeChar;
					}
					if (rs > 7) {
						rs = 1;
						ls = 7;
						r = nc;
						continue;
					}
					int r1 = nc;
					nc = (nc << ls) & 0xFF;
					nc = nc | r;
					r = r1 >> rs;
					rs++;
					ls--;
					result.Add((byte)nc);
				}
				return result.ToArray();
			}
		}

	}
}
