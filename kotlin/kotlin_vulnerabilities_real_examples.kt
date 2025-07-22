// Real Vulnerability Examples for KOTLIN

// Rule ID: 546 - Use of a Broken or Risky Cryptographic Algorithm
// Description: The code uses the SHA-1 hashing algorithm, which is no longer secure due to known weaknesses that allow attackers to create hash collisions. Using SHA-1 for cryptographic purposes can lead to compromised data integrity and authentication.
import java.security.MessageDigest

val input = "password"
val md = MessageDigest.getInstance("SHA-1")
val digest = md.digest(input.toByteArray())
println(digest.joinToString(""))

// Rule ID: 547 - Inadequate Encryption Strength
// Description: The code generates or uses RSA keys that are smaller than 2048 bits, which does not meet current security standards. Such weak keys can be broken more easily by attackers, compromising the encryption.
import java.security.KeyPairGenerator

val keyGen = KeyPairGenerator.getInstance("RSA")
keyGen.initialize(1024)  // Weak key size
val keyPair = keyGen.generateKeyPair()

// Rule ID: 548 - Use of Weak Hash
// Description: The code uses the MD5 hash algorithm, which is outdated and vulnerable to collision attacks. MD5 should not be used for hashing sensitive data or as part of cryptographic operations.
import java.security.MessageDigest

val password = "12345"
val md = MessageDigest.getInstance("MD5")
val hash = md.digest(password.toByteArray())
println(hash.joinToString(""))

// Rule ID: 549 - Use of a Broken or Risky Cryptographic Algorithm
// Description: The code uses NullCipher, which does not actually encrypt data—any sensitive information remains as plain text. This means data meant to be protected is left unencrypted and exposed.
// TODO: Add real Kotlin code here

// Rule ID: 550 - Reusing a Nonce, Key Pair in Encryption
// Description: The code uses AES-GCM encryption but may be reusing the same Initialization Vector (IV) or nonce with the same key. This makes encrypted data vulnerable because identical IVs allow patterns to be detected in the ciphertext.
// TODO: Add real Kotlin code here

// Rule ID: 551 - Improper Authentication
// Description: The code allows anonymous binding to an LDAP server, meaning users can connect without providing any authentication. This makes it possible for anyone to query or interact with your LDAP directory without verifying their identity.
import javax.naming.directory.InitialDirContext

val env = mapOf("java.naming.factory.initial" to "com.sun.jndi.ldap.LdapCtxFactory",
                "java.naming.provider.url" to "ldap://localhost:389")
val ctx = InitialDirContext(java.util.Hashtable(env))  // Anonymous bind

// Rule ID: 552 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
// Description: The code creates cookies without setting the 'secure' flag, allowing them to be sent over unencrypted HTTP connections. This exposes sensitive cookie data to interception by attackers on the network.
// TODO: Add real Kotlin code here

// Rule ID: 553 - Inadequate Encryption Strength
// Description: Using DefaultHttpClient is insecure because it is deprecated and does not support modern TLS 1.2 encryption. This means data sent over the network may not be properly protected.
// TODO: Add real Kotlin code here

// Rule ID: 554 - Use of a Broken or Risky Cryptographic Algorithm
// Description: The code uses the ECB (Electronic Codebook) mode for encryption, which always produces the same output for identical input blocks. This makes it easy for attackers to detect patterns and potentially reveal sensitive information.
// TODO: Add real Kotlin code here

// Rule ID: 555 - Cleartext Transmission of Sensitive Information
// Description: The code creates a network socket without encryption, which means data sent over the connection is transmitted in plain text. This makes it easy for attackers to intercept and read sensitive information.
// TODO: Add real Kotlin code here

// Rule ID: 556 - Sensitive Cookie Without 'HttpOnly' Flag
// Description: The code creates or sets cookies without enabling the 'HttpOnly' flag, which allows client-side scripts (like JavaScript) to access these cookies. This makes sensitive information stored in cookies more accessible to attackers using cross-site scripting (XSS) attacks.
// TODO: Add real Kotlin code here

// Rule ID: 557 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Description: Building command strings for Runtime.exec or loadLibrary using string concatenation or formatting with user-influenced variables is unsafe. This allows attackers to inject malicious commands if inputs aren't properly validated or sanitized.
// TODO: Add real Kotlin code here

// Rule ID: 558 - Incorrect Type Conversion or Cast
// Description: Using Integer.toHexString() to convert hash or byte data to a hex string can strip leading zeroes from each byte, resulting in inconsistent or incorrect representations. This can cause different byte values to appear the same in the output.
// TODO: Add real Kotlin code here

// Rule ID: 559 - Use of Hard-coded Credentials
// Description: The code stores a password or secret value directly in the build.gradle.kts file. Hard-coding sensitive information in source code makes it easy for attackers or unauthorized users to access these secrets if the code is exposed.
// TODO: Add real Kotlin code here

