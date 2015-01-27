using System;
using System.Collections.Generic;
using AdiIRCAPI;

namespace AdiIRC_Encrypt {
	public class PMKeyContainer {
		private Dictionary<string, PMKey> store;
		
		public PMKeyContainer() {
			store = new Dictionary<string, PMKey>();
		}
		
		public bool HasKey(string user) {
			return ((store.ContainsKey(user)) && (store[user].SharedKey != null));
		}
		
		public PMKey this[string key] {
			get {
				if (store.ContainsKey(key)) {
					return store[key];
				}
				PMKey result = new PMKey(key);
				store.Add(key, result);
				return result;
			}
			set {
				if (store.ContainsKey(key)) {
					store.Remove(key);
				}
				store.Add(key, value);
			}
		}
		
	}
}
