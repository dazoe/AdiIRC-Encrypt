using System;
using AdiIRCAPI;

namespace AdiIRC_Encrypt {
	public class AdiIRCPlugin : IPlugin {
		private string name = "AdiIRC Encrypt";
		private string description = "Adds encrpytion to private messages using Ellipic Curve Encryption and Salsa20";
		private string author = "Dave Akers";
		private string version = typeof(AdiIRCPlugin).Assembly.GetName().Version.ToString();
		private string email = "dave@dazoe.net";
		private IPluginHost host;
		private ITools tools;

		public string Name { get { return name; } }
		public string Description { get { return description; } }
		public string Author { get { return author; } }
		public string Version { get { return version; } }
		public string Email { get { return email; } }

		public IPluginHost Host {
			get { return host; }
			set { host = value; }
		}
		public ITools Tools {
			get { return tools; }
			set { tools = value; }
		}
		
		private PMEncrypt pmEncrypt;

		public void Initialize() {
			pmEncrypt = new PMEncrypt(host, tools);
		}
		public void Dispose() {
			pmEncrypt.Dispose();
		}
	}
}
