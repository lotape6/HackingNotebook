### Steps to Generate a Client Certificate
#### **1. Generate a Private Key for the Client**
The client certificate requires its own private key. Generate one as follows:

```bash
openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:2048
```
#### **2. Create a Certificate Signing Request (CSR)**
Use the client private key to create a CSR. The CSR includes the client's information that will be signed by the CA.
```bash
openssl req -new -key client.key -out client.csr
```
During this process, you'll be prompted to provide information like Common Name (CN), Organization, etc. The **CN** is typically your identity (e.g., username or email address) that the server expects.
#### **3. Sign the CSR Using the CA Private Key**
Use the CA's private key (`ca.key`) and the CA's certificate (e.g., `ca.crt`) to sign the CSR and create the client certificate.
```bash
openssl x509 -req -in client.csr -CA server_cert.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
```

Explanation:

- `-req`: Indicates that you're providing a CSR for signing.
- `-CA`: Specifies the server's CA certificate.
- `-CAkey`: Specifies the CA private key.
- `-CAcreateserial`: Creates a serial number file for the CA if it doesn't already exist.
- `-days 365`: Sets the validity period of the client certificate to 1 year.
- `-sha256`: Uses SHA-256 as the hashing algorithm.

#### **4. Verify the Client Certificate**

Ensure the client certificate is correctly signed by the CA:
`openssl verify -CAfile server_cert.crt client.crt`
#### **5. Combine the Client Certificate and Private Key**
To use the client certificate in a browser or a tool, you may need to combine the certificate and private key into a single file in **PKCS#12** format:
```bash
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile server_cert.crt
```

- `-export`: Exports to PKCS#12 format.
- `-out client.p12`: The output file.
- `-inkey client.key`: The client private key.
- `-in client.crt`: The client certificate.
- `-certfile server_cert.crt`: Includes the CA certificate for validation.

You'll be prompted to set a password for the `.p12` file.

#### **6. Provide the Client Certificate**

- Use the `.p12` file for importing into your browser or application.
- Alternatively, provide `client.crt` and `client.key` separately if the server expects them in that format.

---

### Summary of Required Files

- **Client Private Key**: `client.key`
- **Client Certificate**: `client.crt`
- **CA Certificate (Server's Certificate)**: `server_cert.crt`
- (Optional) **PKCS#12 File**: `client.p12`