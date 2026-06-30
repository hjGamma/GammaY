# Distributed Identity Authentication System

## Overview
This project implements a **high-security and user-friendly distributed identity authentication scheme** built on modern cryptographic techniques, including:

- **BLS Signatures**  
- **Zero-Knowledge Proofs (gnark)**  
- **Schnorr Commitments**  

## Key Features
- **Privacy-Preserving Authentication**  
  Multiple independent authority nodes collaboratively issue a universal identity to users **without communicating with each other**.  
  During authentication, users can **prove their identity without revealing any private data**.  

- **User-Centric Data Ownership**  
  The storage rights of identity information are **returned to the users themselves**.  
  Enterprises and third parties will **no longer store any data containing sensitive personal information**.  

- **Secure and Reliable Infrastructure**  
  - Utilizes **OpenSSL** to generate certificate files for authentication and encryption.  
  - Employs **gRPC** to enable secure and efficient communication between distributed nodes.  

## Benefits
- Strong confidentiality ensured by advanced cryptography.  
- Maximum privacy protection with user-controlled data.  
- Lightweight and convenient for real-world identity verification scenarios.  
- Secure node-to-node communication powered by **TLS + gRPC**.  

---

✨ This project demonstrates how **state-of-the-art cryptography and distributed systems** can be combined to build a **secure, decentralized, and privacy-preserving identity infrastructure**.
