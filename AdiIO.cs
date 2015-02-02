using System;
using System.Collections.Generic;
using System.Net.Mail;
using System.Threading;
using AdiIRCAPI;

namespace AdiIRC_Encrypt {
	//delegates for events.
	public delegate void OnOldUserHasPluginHandler(IServer server, string prefix);
	public delegate void OnOldProtocolHandler(IServer server, string prefix, byte[] data);
	public delegate byte[] OnOldEncryptedMessage(IServer server, string prefix, byte[] data);

	public class AdiIO : IDisposable {
		public IPluginHost Host { get; set; }
		public ITools Tools { get; set; }
		private Thread sendMessageThread;
		private bool sendMessageThreadRun;
		private int mSecondsPerMessage;
		public int SendMessageRate {
			get {
				return (int)(1000 / mSecondsPerMessage);
			}
			set {
				mSecondsPerMessage = (int)(1000 / value);
			}
		}
		private Queue<Tuple<IServer, byte[]>> outputMessages;
		private Dictionary<string, Tuple<IServer, string, byte[]>> incommingMessages;

		//Old protocol stuff
		private readonly byte[] msgPluginTag = new byte[]{ 0x02, 0x1d, 0x02, 0x1d }; //bibi
		private const byte msgKeyEnquire = 0x05;
		private const byte msgKeyAcknowledge = 0x06;
		private const byte msgEncrypted = 0x07;
		//New protocol
		private const byte msgMyProtocol = 0x04;
		private readonly byte[] CRLF = new byte[]{0x0D, 0x0A};
		
		//Events
		public OnOldUserHasPluginHandler OnUserHasPlugin;
		public OnOldProtocolHandler OnKeyEnquire;
		public OnOldProtocolHandler OnKeyAcknowledge;
		public OnOldEncryptedMessage OnMsgEncrypted;
		
		
		public AdiIO(IPluginHost Host, ITools Tools) {
			this.Host = Host;
			this.Tools = Tools;
			outputMessages = new Queue<Tuple<IServer, byte[]>>();
			incommingMessages = new Dictionary<string, Tuple<IServer, string, byte[]>>();
			sendMessageThread = new Thread(SendMessageThread);
			sendMessageThreadRun = true;
			sendMessageThread.Start();
			Host.OnRawData += OnRawData;
		}

		private void DoOnUserHasPlugin(IServer server, string prefix) {
			if (OnUserHasPlugin != null) {
				OnUserHasPlugin(server, prefix);
			}
		}
		private void DoOnKeyEnquire(IServer server, string prefix, byte[] data) {
			if (OnKeyEnquire != null) {
				OnKeyEnquire(server, prefix, data);
			}
		}
		private void DoOnKeyAcknowledge(IServer server, string prefix, byte[] data) {
			if (OnKeyAcknowledge != null) {
				OnKeyAcknowledge(server, prefix, data);
			}
		}
		private byte[] DoOnMsgEncrypted(IServer server, string prefix, byte[] data) {
			byte[] result = null;
			if (OnMsgEncrypted != null) {
				result = OnMsgEncrypted(server, prefix, data);
			}
			return result;
		}
		
		private void OnRawData(object sender, RawDataArgs e) {
			// Need to capture PRIVMSGs from users and to channels.
			if (e.Bytes[0] != ':')
				return; //Ignore anything that doesn't have a prefix.
			int offset = 1;
			int spaceIdx = Array.IndexOf<byte>(e.Bytes, 0x20, offset);
			if (spaceIdx <= offset) {
				Host.NotifyUser("AdiIRC Encrypt: couldn't find space after prefix");
				return;
			}
			string prefix = e.Server.Encoding.GetString(e.Bytes, offset, spaceIdx - offset);
			offset = spaceIdx + 1;
			spaceIdx = Array.IndexOf<byte>(e.Bytes, 0x20, offset);
			if (spaceIdx <= offset) {
				//couldn't find space after command, so it's not a PRIVMSG
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
				foreach (char c in e.Server.ChannelPrefix + e.Server.UserPrefix) {
					if (args[0][0] == c) {
						goto KeepParsing;
					}
				}
				// if the foreach fails then target is not a channel or me.
				return;
			}
		KeepParsing:
			// It's a PRIVMSG to a channel i'm in or to me directly
			if ((trailing != null) && (trailing.Length <= 4)) {
				return;
			}
			if (args[0] == e.Server.Nick) {
				// direct PM stuff here, IE: old protocol stuff.
				if (trailing.StartsWith(msgPluginTag)) {
					DoOnUserHasPlugin(e.Server, prefix);
					return;
				}
				switch (trailing[0]) {
					case msgKeyEnquire:
						DoOnKeyEnquire(e.Server, prefix, trailing.SubArray(1));
						e.Bytes = new byte[0];
						return;
					case msgKeyAcknowledge:
						DoOnKeyAcknowledge(e.Server, prefix, trailing.SubArray(1));
						e.Bytes = new byte[0];
						return;
					case msgEncrypted:
						byte[] result = DoOnMsgEncrypted(e.Server, prefix, trailing.SubArray(1));
						if (result == null) {
							return; //Let bytes pass through?
						}
						e.Bytes = e.Bytes.SubArray(0, offset); //Everything upto and including the :
						e.Bytes = e.Bytes.Concatenate(result); //tack on the message. 
						return;
				}
			}
			
			// New protocol stuff.
			if (trailing[0] == msgMyProtocol) {
				//TODO: this is our new protocol.
			}
		}

		private void SendMessageThread() {
			while (sendMessageThreadRun) {
				if (outputMessages.Count > 0) {
					// The outputQueue will be pre-formatted so all we need to do is send it.
					Tuple<IServer, byte[]> message = outputMessages.Dequeue();
					message.Item1.SendRawData(message.Item2);
				}
				Thread.Sleep(mSecondsPerMessage);
			}
		}
		public void Dispose() {
			sendMessageThreadRun = false;
			sendMessageThread.Join(mSecondsPerMessage * 2);
		}
	}
}
