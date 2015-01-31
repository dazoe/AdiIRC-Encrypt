using System;
using System.Collections.Generic;
using AdiIRCAPI;
using Chaos.NaCl;

namespace AdiIRC_Encrypt {
	public class PMKeyContainer {
		private Dictionary<string, PMKey> store;
		
		public PMKeyContainer() {
			store = new Dictionary<string, PMKey>();
		}
		
		public bool HasKey(string idx) {
			return ((store.ContainsKey(idx)) && (store[idx].SharedKey != null));
		}
		public void DeleteKey(string idx) {
			if (store.ContainsKey(idx)) {
				store.Remove(idx);
			}
		}
		public PMKey this[string idx] {
			get {
				if (store.ContainsKey(idx)) {
					return store[idx];
				}
				PMKey result = new PMKey(idx);
				store.Add(idx, result);
				return result;
			}
			set {
				if (store.ContainsKey(idx)) {
					store.Remove(idx);
				}
				store.Add(idx, value);
			}
		}
		
	}
}
