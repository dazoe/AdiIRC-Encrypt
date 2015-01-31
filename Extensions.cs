using System;
using System.Collections.Generic;
using System.Reflection;
using AdiIRCAPI;
using Chaos.NaCl;

namespace System.Runtime.CompilerServices {
	[AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class
	| AttributeTargets.Method)]
	public sealed class ExtensionAttribute : Attribute { }
}

namespace AdiIRC_Encrypt {
	public static class Extensions {
		private const byte escapeChar = 0x21; 
		private static Assembly adiIRC = null;
		// Extending the server API
		public static bool SendFakePrivMessage(this IServer server, IUser source, string msg) {
			string line = string.Format(":{0}!{1}@{2} PRIVMSG {3} :{4}", source.Nick, source.Ident, source.Host, server.UserNick, msg);
			return server.SendFakeRaw(line);
		}
		//TODO: remove this bit of hackery when the API is updated.
		private static Assembly GetAdiIRCAssembly() {
			if (adiIRC == null) {
				Assembly[] allAssemblies = AppDomain.CurrentDomain.GetAssemblies();
				for (int i = 0; i < allAssemblies.Length; i++) {
					if (allAssemblies[i].GetName().Name == "AdiIRC") {
						adiIRC = allAssemblies[i];
						break;
					}
				}
			}
			return adiIRC;
		}
		public static IUser FindUser(this IServer server, string prefix) {
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			Type serverT = GetAdiIRCAssembly().GetType("AdiIRC.IRC.Core.Server");
			MethodInfo mi = serverT.GetMethod("FindUser", BindingFlags.NonPublic | BindingFlags.Instance);
			return mi.Invoke(server, new object[]{ prefix }) as IUser;
		}

		// Extending byte[]
		public static byte[] SubArray(this byte[] data, int startIdx, int length = 0) {
			if (length <= 0) {
				length = (data.Length - startIdx) + length;
			}
			byte[] result = new byte[length];
			Array.Copy(data, startIdx, result, 0, length);
			return result;
		}
		public static bool StartsWith(this byte[] data, byte[] start) {
			if ((start == null) || (data.Length < start.Length))
				return false;
			for (int i = 0; i < start.Length; i++) {
				if (data[i] != start[i])
					return false;
			}
			return true;
		}
		public static byte[] ReadBase64(this string data) {
			return CryptoBytes.FromBase64String(data);
		}
		public static byte[] IrcEscape(this byte[] data) {
			List<byte> result = new List<byte>();
			for (int i = 0; i < data.Length; i++) {
				if ((data[i] == 0x00) || (data[i] == 0x0A) || (data[i] == 0x0D) || (data[i] == escapeChar)) {
					result.Add(escapeChar);
					result.Add((byte)(data[i] + escapeChar));
					continue;
				}
				result.Add(data[i]);
			}
			return result.ToArray();
		}
		public static byte[] IrcUnescape(this byte[] data) {
			List<byte> result = new List<byte>();
			for (int i = 0; i < data.Length; i++) {
				if (data[i] == escapeChar) {
					result.Add((byte)(data[++i] - escapeChar));
					continue;
				}
				result.Add(data[i]);
			}
			return result.ToArray();
		}
		public static byte[] Concatenate(this byte[] data, params byte[][] args) {
			int totalLength = data.Length;
			foreach (byte[] arg in args) {
				totalLength += arg.Length;
			}
			byte[] result = new byte[totalLength];
			data.CopyTo(result, 0);
			int offset = data.Length;
			foreach (byte[] arg in args) {
				arg.CopyTo(result, offset);
				offset += arg.Length;
			}
			return result;
		}

		// Extending string
		public static int IndexOf(this byte[] data, byte needle, int skipCount = 0) {
			for (int i = 0; i < data.Length; i++) {
				if ((data[i] == needle) && (skipCount-- == 0))
					return i;
			}
			return -1;
		}
		public static string ToBase64String(this byte[] data) {
			return CryptoBytes.ToBase64String(data);
		}
	}
}
