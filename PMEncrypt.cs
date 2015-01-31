using System;
using System.Collections.Generic;
using System.Text;
using AdiIRCAPI;
using Chaos.NaCl;

namespace AdiIRC_Encrypt {
	public class PMEncrypt : IDisposable {
		private PMKeyContainer keys;
		private List<string> hasPluginSent;
		private IPluginHost host;
		private ITools tools;

		private readonly byte[] msgPluginTag = new byte[]{ 0x02, 0x1d, 0x02, 0x1d }; //bibi
		private const string msgPluginTagStr = "\x02\x1d\x02\x1d"; //bibi
		private const byte msgKeyEnquire = 0x05;
		private const byte msgKeyAcknowledge = 0x06;
		private const byte msgEncrypted = 0x07;
		private readonly byte[] CRLF = new byte[]{0x0D, 0x0A};
		private byte[] msgEncryptedIndicator = Encoding.ASCII.GetBytes("{X}");

		public PMEncrypt(IPluginHost Host, ITools Tools) {
			keys = new PMKeyContainer();
			hasPluginSent = new List<string>();
			host = Host;
			tools = Tools;
			
			host.OnRawData += OnRawData;
			host.OnSendData += OnSendData;
		}
		
		private void SendMyKey(IServer server, string prefix, byte responseType, bool generateNew = false) {
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			if (generateNew) {
				keys.DeleteKey(prefix);
			}
			string message = string.Format("PRIVMSG {0} :", prefix);
			server.SendRawData(server.Encoding.GetBytes(message).Concatenate(new byte[]{responseType}, keys[prefix].MyPublicKey.IrcEscape(), CRLF));
			host.NotifyUser(server.FindUser(prefix), string.Format("Sending public key {0:X}", responseType));
		}
		private void OnKeyEnquire(IServer server, string prefix, byte[] trailing) {
			// Recived PUB key, the other end still needs ours.
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			keys[prefix].SetUsersPublicKey(trailing.SubArray(1).IrcUnescape());
			SendMyKey(server, prefix, msgKeyAcknowledge);
			host.NotifyUser(server.FindUser(prefix), string.Format("Received public key {0:X}", msgKeyEnquire));
		}
		private void OnKeyAcknowledge(IServer server, string prefix, byte[] trailing) {
			// Received PUB key, the other end already has ours.
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			keys[prefix].SetUsersPublicKey(trailing.SubArray(1).IrcUnescape());
			host.NotifyUser(server.FindUser(prefix), string.Format("Received public key {0:X}", msgKeyAcknowledge));
		}
		private byte[] EncryptMessage(string prefix, byte[] message) {
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			byte[] nonce = RNG.GetBytes(24);
			byte[] key = keys[prefix].SharedKey;
			byte[] encMsg = XSalsa20Poly1305.Encrypt(message, key, nonce);
			return nonce.Concatenate(encMsg);
		}
		private byte[] DecryptMessage(string prefix, byte[] message, int startIdx = 0) {
			if (prefix.Contains("!")) {
				prefix = prefix.Substring(0, prefix.IndexOf('!'));
			}
			byte[] result = null;
			if (keys.HasKey(prefix)) {
				byte[] nonce = message.SubArray(startIdx, 24);
				byte[] key = keys[prefix].SharedKey;
				byte[] encMsg = message.SubArray(startIdx + 24);
				result = XSalsa20Poly1305.TryDecrypt(encMsg, key, nonce);
				if (result != null) {
					result = msgEncryptedIndicator.Concatenate(result);
				}
			}
			return result;
		}

		private void OnRawData(object sender, RawDataArgs e) {
			// Raw Data from server.
			if (e.Bytes[0] != ':')
				return; //Ignore anything that doesn't have a prefix because PRIVMSGs sent to us will/should be prefixed
			int offset = 1;
			int spaceIdx = Array.IndexOf<byte>(e.Bytes, 0x20, offset);
			if (spaceIdx <= offset) {
				host.NotifyUser("AdiIRC Encrypt: couldn't find space after prefix");
				return;
			}
			string prefix = e.Server.Encoding.GetString(e.Bytes, offset, spaceIdx - offset);
			offset = spaceIdx + 1;
			spaceIdx = Array.IndexOf<byte>(e.Bytes, 0x20, offset);
			if (spaceIdx <= offset) {
				host.NotifyUser("AdiIRC Encrypt: couldn't find space after command");
				return;
			}
			string command = e.Server.Encoding.GetString(e.Bytes, offset, spaceIdx - offset);
			if (command.ToUpper() != "PRIVMSG") {
				return; //Don't care about anything other than PRIVMSGs.
			}
			List<string> argsList = new List<string>();
			byte[] trailing = null;
			string arg;
			while (true) {
				offset = spaceIdx + 1;
				if (e.Bytes[offset] == ':') { //the trailing part!
					offset++;
					trailing = e.Bytes.SubArray(offset);
					break;
				}
				spaceIdx = Array.IndexOf<byte>(e.Bytes, 0x20, offset);
				if (spaceIdx <= offset) {
					break;
				}
				arg = e.Server.Encoding.GetString(e.Bytes, offset, spaceIdx - offset);
				argsList.Add(arg);
			}
			string[] args = argsList.ToArray();
			// phew, now we should have a privmsg, the sender is prefix and target is args[0] and the message is in trailing
			if (args[0] != e.Server.Nick) {
				return; //Don't care about channels here.
			}
			//It's a PRIVMSG to ME!
			//Do we need to mess with it?
			if ((trailing != null) && (trailing.Length <= 4)) {
				// host.NotifyUser("AdiIRC Encrypt: trailing was null or too small."); //Will interfear with small messages from non AdiIRC Encrypt clients.
				return;
			}
			switch (trailing[0]) {
				case msgKeyEnquire:
					// Recived PUB key, the other end still needs ours.
					OnKeyEnquire(e.Server, prefix, trailing);
					e.Bytes = new byte[0]; //Eat it, TODO: replace with null when the API is updated.
					break;
				case msgKeyAcknowledge:
					// Received PUB key, the other end already has ours.
					OnKeyAcknowledge(e.Server, prefix, trailing);
					e.Bytes = new byte[0]; //Eat it, TODO: replace with null when the API is updated.
					break;
				case msgEncrypted:
					//Encrypted message, decrypt it and pass it on.
					host.NotifyUser("Received Data: " + trailing.SubArray(1).ToBase64String());
					byte[] decMsg = DecryptMessage(prefix, trailing.IrcUnescape(), 1);
					e.Bytes = e.Bytes.SubArray(0, offset); //Everything upto and including the :
					e.Bytes = e.Bytes.Concatenate(decMsg); //tack on the message. 
					break;
			}
			if (trailing.StartsWith(msgPluginTag)) {
				//A plain text message from someone that has the AdiIRC Encrypt, send them a public key
				SendMyKey(e.Server, prefix, msgKeyEnquire, true);
				//Let the message pass as is, msgPluginTag is invisible
		    }
		}

		private void OnSendData(IServer server, string data, out EatData result) {
			result = EatData.EatNone;
			string[] args = data.Split(new char[]{ ' ' }, 3);
			if (args[0].ToUpper() != "PRIVMSG") {
				return; //We only care about PRIVMSGs
			}
			char targetPrefix = args[1][0];
			foreach (char c in server.ChannelPrefix + server.UserPrefix) {
				if (targetPrefix == c) {
					return; //We don't care about channels either.
				}
			}
			if (args[2][1] == 0x01) {
				return; // don't mess with CTCP
			}
			//Now we have a privmsg being sent to a user. target is args[1] and the message is args[2] including the ':' prefix
			if (keys.HasKey(args[1])) {
				//We have a key for the user, Encrypt the message.
				string msgStart = string.Format("PRIVMSG {0} :", args[1]);
				byte[] msgData = EncryptMessage(args[1], server.Encoding.GetBytes(args[2].Substring(1))).IrcEscape();
				host.NotifyUser("Sending Data: " + msgData.ToBase64String());
				server.SendRawData(server.Encoding.GetBytes(msgStart).Concatenate(new byte[]{ msgEncrypted }, msgData, CRLF));
				result = EatData.EatAll;
				return;
			}
			if (!hasPluginSent.Contains(args[1])) {
				//We have not sent the "has plugin" tag yet.
				hasPluginSent.Add(args[1]);
				string message = string.Format("PRIVMSG {0} :{1}{2}", args[1], msgPluginTagStr, args[2].Substring(1));
				server.SendRawData(server.Encoding.GetBytes(message).Concatenate(CRLF));
				result = EatData.EatAll;
				return;
			}
		}

		public void Dispose() {
		}
	}
}
