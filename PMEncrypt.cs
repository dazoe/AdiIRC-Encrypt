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
		private string lastRawSent;

		private const string msgHasPluginTag = "\x02\x02\x1d\x1d"; //bbii
		private const string msgPluginMsg = "\x02\x1d\x02\x1d"; //bibi
		private const string msgEncryptedTag = "\x02\x1d\x1d\x02"; //biib
		private const string msgUnused0Tag = "\x1d\x1d\x02\x02"; //iibb
		private const string msgUnused1Tag = "\x1d\x02\x1d\x02"; //ibib
		private const string msgUnused2Tag = "\x1d\x02\x02\x1d"; //ibbi
		
		public PMEncrypt(IPluginHost Host, ITools Tools) {
			keys = new PMKeyContainer();
			hasPluginSent = new List<string>();
			host = Host;
			tools = Tools;
			
			host.OnPrivateMessage += OnPrivateMessage;
			host.OnSendData += OnSendData;
		}

		private void OnPrivateMessage(IServer server, IUser user, string message, out EatData result) {
			result = EatData.EatNone;
			// We have received a message from a user.
			if (message.Length < 4)
				return;
			string msgTag = message.Substring(0, 4);
			switch (msgTag) {
				case msgHasPluginTag:
					// user has the plugin, which means we can send messages and have them intercepted...
					// Send our Pub Key.
					lastRawSent = string.Format("PRIVMSG {0} :{1}", user.Nick, msgPluginMsg + "PK1" + keys[user.Nick].MyPublicKey.ToBase64String());
					server.SendRaw(lastRawSent);
					// We eat this and use a fake send to let our message be below the original message.
					result = EatData.EatAll;
					server.SendFakePrivMessage(user, message);
					host.NotifyUser(user, "Sending public key...");
					break;
				case msgPluginMsg:
					// A message ment for the plugin and to be eaten, this is where the handsake would be.
					//TODO: need to add bounds checking.
					//TODO: need to think about the possibility of things out of order.
					string msgType = message.Substring(4, 3);
					switch (msgType) {
						case "PK1":
							// a response to "HasPlugin" tag. store the key and send ours.
							keys[user.Nick].SetUsersPublicKey(message.Substring(7).ReadBase64());
							lastRawSent = string.Format("PRIVMSG {0} :{1}", user.Nick, msgPluginMsg + "PK2" + keys[user.Nick].MyPublicKey.ToBase64String());
							server.SendRaw(lastRawSent);
							host.NotifyUser(user, "Received public key, sending ours");
							result = EatData.EatAll;
							break;
						case "PK2":
							// a response to PK1, at this point we should have a priv key already and can create a shared key.
							keys[user.Nick].SetUsersPublicKey(message.Substring(7).ReadBase64());
							host.NotifyUser(user, "Received public key.");
							result = EatData.EatAll;
							break;
					}
					break;
				case msgEncryptedTag:
					// An encrypted message, attempt to decrypt it.
					if (keys.HasKey(user.Nick)) {
						byte[] data = message.Substring(4).ReadBase64();
						byte[] msgData = XSalsa20Poly1305.TryDecrypt(data.SubArray(24), keys[user.Nick].SharedKey, data.SubArray(0, 24));
						if (msgData == null) {
							host.NotifyUser(user, "Failed to decrypt message! Sending public key again.");
							break;
						}
						server.SendFakePrivMessage(user, "{X} " + Encoding.UTF8.GetString(msgData));
						result = EatData.EatAll;
					} else {
						server.SendFakePrivMessage(user, message);
						host.NotifyUser(user, "Don't have key for encrypted message");
						server.SendRaw(string.Format("PRIVMSG {0} :{1}", user.Nick, "Could not decrypt last message."));
						result = EatData.EatAll;
					}
					break;
			}
		}

		private void OnSendData(IServer server, string data, out EatData result) {
			result = EatData.EatNone;
			if (data == lastRawSent)
				return;

			string[] args = data.Split(new char[] { ' ' }, 3);
			if (args[0].ToLower() == "privmsg") {
				char prefix = args[1][0];
				foreach (char c in server.ChannelPrefix + server.UserPrefix) {
					if (c == prefix) {
						return;
					}
				}
				//OK it's a PRIVMSG to a USER... and args[2] should be the entire message other than the ':' prefix
				if (keys.HasKey(args[1])) {
					byte[] nonce = RNG.GetBytes(24);
					byte[] encMsg = XSalsa20Poly1305.Encrypt(Encoding.UTF8.GetBytes(args[2].Substring(1)), keys[args[1]].SharedKey, nonce);
					string encMessage = msgEncryptedTag + nonce.ToBase64String() + encMsg.ToBase64String();
					lastRawSent = string.Format("PRIVMSG {0} :{1}", args[1], encMessage);
					server.SendRaw(lastRawSent);
					result = EatData.EatAll;
					return;
				}
				//attach the "HasPlugin" tag so the other end knows we have the plugin.
				if (!hasPluginSent.Contains(args[1])) {
					hasPluginSent.Add(args[1]);
					string message = msgHasPluginTag + args[2].Substring(1);
					lastRawSent = string.Format("PRIVMSG {0} :{1}", args[1], message);
					server.SendRaw(lastRawSent);
					result = EatData.EatAll;
					return;
				}
			}
		}
		public void Dispose() {
		}
	}
}
