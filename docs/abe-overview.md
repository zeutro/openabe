# Attribute-Based Encryption in OpenABE

## What is Attribute-Based Encryption (ABE)?

Encryption is a method of encoding data that protects the confidentiality of its contents from unauthorized attackers. Traditionally, encryption was viewed as a tool to enable secure communication between a sender and a targeted recipient of information. For example, one might wish to store a message such that it can only be decrypted by the user bob@xyz.org.

Attribute-Based Encryption is a more expansive type of public key encryption that allows for flexible policy-based access controls that are cryptographically (that is, mathematically) enforced. Instead of encrypting data to a single user, it is now possible to encrypt it so that the data can be decrypted by anyone with credentials satisfying an arbitrary attribute-based access control policy.

In OpenABE, any string can potentially serve as an attribute. In addition, attributes can be numeric values and policies can contain ranges over these values. The set of attributes used will depend on the designated application.

In order to understand the capabilities of ABE, it helps to organize them logically into three variants.

### Content-Based Access Control

For granting selective access later (e.g., cloud, email, big data, subpoenas).

In an ABE system for content-based access control, attributes are associated with a ciphertext and the private key is associated with a policy over these attributes. (In academic literature, this variant is sometimes referred to as "Key-Policy" ABE.)

For example, a company could automatically encrypt all of its emails with the attributes being some (or all) of the 75 fields in Mail headers and then later the company can distribute a key to an analyst that allows for decryption of all emails that meet the policy of `To:engineering@corporation.com` OR (subject contains `cascade project` AND sent between `Dec 21, 2017` and `Jan 10, 2018`).

### Role-Based Access Control

For policies known at the time of encryption (e.g., classified documents, medical records).

An ABE system for role-based access control "flips" the semantics of content-based access control. In such a system, attributes are associated with a private key and a policy (or boolean formula) is associated with the ciphertext. Here the attributes are often associated with the credentials of a private key holder. (In academic literature this variant is sometimes referred to as "Ciphertext-Policy" ABE.) For instance, one could restrict a ciphertext only to female employees who have been with the company since 2012 and worked on the "HALE" software project.

### Multi-Authority Role-Based Access Control

For operating across organizational boundaries.

One issue with role-based access control is that in many applications you may need to write access control policies that span across different administrative boundaries. In standard ABE, there is one authority that hands out private keys. However, in some applications, it is natural for different authorities to manage different attributes. A multi-authority ABE system allows one to associate a ciphertext with a policy written across attributes issued by different authorities. These authorities can operate independently and do not have to coordinate (or even be aware of) each other.

For instance, the government might certify the attributes in a person's driver's license (such as age), while a credit score company could distribute credentials about a user's credit score and an employer could distribute credentials about its employees. With this type of ABE, one can now send out a special offer readable by anyone over age 50 with a strong credit score and a job at a local employer.

## What cryptographic algorithms are implemented in OpenABE?

OpenABE is a C/C++ software library offering several attribute-based encryption (ABE) schemes together with other core cryptographic functionalities such as authenticated symmetric-key encryption, public key encryption, digital signatures, X.509 certificate handling, key derivation functions, pseudorandom generators and more.

Application developers should not need to be cryptographic experts to use ABE. To make OpenABE as secure and user-friendly as possible, the following features are provided by default:

1. **Collusion-Resistant**: Common pitfall in ABE scheme development; Alice and Bob should not be able to combine their private keys to decrypt a ciphertext that neither can decrypt on their own. Note: any attempt to "engineer" ABE from standard public key encryption usually falls to this attack.
2. **Chosen Ciphertext Attack (CCA) Secure**: Prevents serious and practical tampering attacks; most existing schemes in the academic literature only satisfy a weaker security notion (CPA-security).
3. **Unrestricted Attributes**: Attributes can be represented by any string (alternative: must enumerate every current and future attribute at system initialization) and can be used an unlimited number of times in a policy.

OpenABE comes with support for efficient and optimized implementations of content-based and role-based ABE schemes.

For the full cryptographic technical details inside OpenABE, see the [OpenABE Design Document](libopenabe-v1.0.0-design-doc.pdf).
