//
//  ContentView.swift
//  TestSEP
//
//  Created by Chip on 11/3/21.
//

import SwiftUI

extension Data {
    // From http://stackoverflow.com/a/40278391:
    init?(fromHexEncodedString string: String) {

        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeNibble(u: UInt16) -> UInt8? {
            switch(u) {
            case 0x30 ... 0x39:
                return UInt8(u - 0x30)
            case 0x41 ... 0x46:
                return UInt8(u - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(u - 0x61 + 10)
            default:
                return nil
            }
        }

        self.init(capacity: string.utf16.count/2)
        var even = true
        var byte: UInt8 = 0
        for c in string.utf16 {
            guard let val = decodeNibble(u: c) else { return nil }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even = !even
        }
        guard even else { return nil }
    }
}

struct ContentView: View {
    @State private var password = ""
    @State private var ciphertext = ""
    @State private var status = ""
    @State private var useSEP = true
    @State private var requireUserPresence = false
    @State private var applicationPassword = false
    @State private var alertShown = false
    @State private var alertMessage = ""
    
    let username = "foo"
    let keyTag = "com.spideroak.TestSEP".data(using: .utf8)!

    var body: some View {
        ScrollView {
            VStack {
                Toggle(isOn: $useSEP) {
                    Text("Use SEP")
                }
                Toggle(isOn: $requireUserPresence) {
                    Text("Require User Presence")
                }
                Toggle(isOn: $applicationPassword) {
                    Text("Application Password")
                }
                HStack {
                    Button(action: createKey) {
                        Text("Create Key")
                    }
                    Button(action: deleteKey) {
                        Text("Delete Key")
                    }
                }
                Divider().padding()
                TextField("Password", text: $password, prompt: Text("Password"))
                    .padding(.bottom, 8.0)
                TextEditor(text: $ciphertext)
                    .frame(height: 100.0)
                    .font(.custom("Menlo", size: 14))
                HStack {
                    Button(action: encryptPassword) {
                        Text("Encrypt")
                    }
                    Button(action: decryptPassword) {
                        Text("Decrypt")
                    }
                }
                Text(status)
                    .padding(.top, 8.0)
            }
            .buttonStyle(.bordered)
            .textFieldStyle(.roundedBorder)
            .padding(12)
            .alert(isPresented: $alertShown) {
                Alert(title: Text("Error"), message: Text(alertMessage))
            }
        }
    }

    func showError(_ message: String) {
        alertMessage = message
        alertShown = true
    }
    
    func showMessage(_ message: String) {
        status = message
    }
    
    func createKey() {
        var error: Unmanaged<CFError>?
        var accessFlags: SecAccessControlCreateFlags = []
        if useSEP {
            accessFlags.insert(.privateKeyUsage)
        }
        if requireUserPresence {
            accessFlags.insert(.biometryAny)
        }
        if applicationPassword {
            accessFlags.insert(.applicationPassword)
        }
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, accessFlags, &error)
        if error != nil {
            showError("Error creating access control: \(String(describing: error))")
            return
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access!,
            ]
        ]
        if useSEP {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            showError("Failed to store keychain item: \(String(describing: error))")
            return
        }

        showMessage("Created key: \(privateKey)")
    }
    
    func encryptPassword() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnRef as String: true,
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            showError("Could not find key: \(status)")
            return
        }
        
        let key = item as! SecKey
        let pubkey = SecKeyCopyPublicKey(key)!
        
        let pwdata = password.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        guard let cfEncData = SecKeyCreateEncryptedData(pubkey, .eciesEncryptionCofactorX963SHA512AESGCM, pwdata as CFData, &error) else {
            showError("Could not encrypt password: \(String(describing: error))")
            return
        }
        let encData = cfEncData as Data
        
        ciphertext = encData.map { String(format:"%02hhX", $0) }.joined()
        password = ""
        showMessage("Encrypted ciphertext")
    }
    
    func decryptPassword() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnRef as String: true,
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            showError("Could not find key: \(status)")
            return
        }
        
        let key = item as! SecKey
        
        let cipherdata = Data(fromHexEncodedString: ciphertext)!
        var error: Unmanaged<CFError>?
        guard let cfCleartext = SecKeyCreateDecryptedData(key, .eciesEncryptionCofactorX963SHA512AESGCM, cipherdata as CFData, &error) else {
            showError("Could not decrypt password: \(String(describing: error))")
            return
        }
        password = String(data: cfCleartext as Data, encoding: .utf8)!
        
        showMessage("Decrypted ciphertext")
    }
    
    func deleteKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            let explanation = SecCopyErrorMessageString(status, nil)!
            showError("Could not find item:" + (explanation as String))
            return
        }
        
        showMessage("key deleted")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
