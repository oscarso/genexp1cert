// genexp1cert.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define	KEY_CONTAINER_NAME	L"ExpOneKeyContainer"
#define	CERT_X500			L"CN=Test"


BOOL CreatePrivateExponentOneKey(
	LPTSTR szProvider,
	DWORD dwProvType,
	LPTSTR szContainer,
	DWORD dwKeySpec,
	HCRYPTPROV *hProv,
	HCRYPTKEY *hPrivateKey
)
{
	BOOL fReturn = FALSE;
	BOOL fResult;
	int n;
	LPBYTE keyblob = NULL;
	DWORD dwkeyblob;
	DWORD dwBitLen;
	BYTE *ptr;

	__try {
		*hProv = 0;
		*hPrivateKey = 0;

		if ((dwKeySpec != AT_KEYEXCHANGE) && (dwKeySpec != AT_SIGNATURE))  __leave;

		// Try to create new container
		fResult = CryptAcquireContext(hProv, szContainer, szProvider, dwProvType, CRYPT_NEWKEYSET);
		if (!fResult) {
			// If the container exists, open it
			if (GetLastError() == NTE_EXISTS) {
				fResult = CryptAcquireContext(hProv, szContainer, szProvider, dwProvType, 0);
				if (!fResult) {
					// No good, leave
					__leave;
				}
			} else {
				// No good, leave
				__leave;
			}
		}

		// Generate the private key
		fResult = CryptGenKey(*hProv, dwKeySpec, CRYPT_EXPORTABLE, hPrivateKey);
		if (!fResult) __leave;

		// Export the private key, we'll convert it to a private
		// exponent of one key
		fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
		if (!fResult) __leave;

		keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
		if (!keyblob) __leave;

		fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
		if (!fResult) __leave;

		CryptDestroyKey(*hPrivateKey);
		*hPrivateKey = 0;

		// Get the bit length of the key
		memcpy(&dwBitLen, &keyblob[12], 4);

		// Modify the Exponent in Key BLOB format
		// Key BLOB format is documented in SDK

		// Convert pubexp in rsapubkey to 1
		ptr = &keyblob[16];
		for (n = 0; n < 4; n++)
		{
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip pubexp
		ptr += 4;
		// Skip modulus, prime1, prime2
		ptr += (dwBitLen / 8);
		ptr += (dwBitLen / 16);
		ptr += (dwBitLen / 16);

		// Convert exponent1 to 1
		for (n = 0; n < (int)(dwBitLen / 16); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip exponent1
		ptr += (dwBitLen / 16);

		// Convert exponent2 to 1
		for (n = 0; n < (int)(dwBitLen / 16); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Skip exponent2, coefficient
		ptr += (dwBitLen / 16);
		ptr += (dwBitLen / 16);

		// Convert privateExponent to 1
		for (n = 0; n < (int)(dwBitLen / 8); n++) {
			if (n == 0) ptr[n] = 1;
			else ptr[n] = 0;
		}

		// Import the exponent-of-one private key
		if (!CryptImportKey(*hProv, keyblob, dwkeyblob, 0, CRYPT_EXPORTABLE, hPrivateKey)) {
			__leave;
		}

		fReturn = TRUE;
	}
	__finally
	{
		if (keyblob) LocalFree(keyblob);

		if (!fReturn)
		{
			if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
			if (*hProv) CryptReleaseContext(*hProv, 0);
		}
	}

	return fReturn;
}


BOOL GenerateSelfSignedCert(
	LPTSTR szProvider,
	DWORD dwProvType,
	LPTSTR szContainer,
	DWORD dwKeySpec
) {
	//Generate self-signed cert and export it
	HCERTSTORE		hStorePort = NULL;
	PCCERT_CONTEXT	pCertContext = NULL;
	BYTE			*pbEncoded = NULL;
	HCERTSTORE		hStoreOpen = NULL;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;
	HANDLE	hFile = NULL;

	__try {
		// Encode certificate Subject
		LPCTSTR pszX500 = CERT_X500;
		DWORD cbEncoded = 0;
		//_tprintf(_T(“CertStrToName… “));
		if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL)) {
			// Error
			printf("CertStrToName(1st) Error=0x%x\n", GetLastError());
			return FALSE;
		}

		//_tprintf(_T(“malloc… “));
		if (!(pbEncoded = (BYTE *)malloc(cbEncoded))) {
			// Error
			//_tprintf(_T(“Error 0x%x\n”), GetLastError());
			return FALSE;
		}

		//_tprintf(_T(“CertStrToName… “));
		if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL)) {
			// Error
			printf("CertStrToName(2nd) Error=0x%x\n", GetLastError());
			return FALSE;
		}

		// Prepare certificate Subject for self-signed certificate
		CERT_NAME_BLOB SubjectIssuerBlob;
		memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
		SubjectIssuerBlob.cbData = cbEncoded;
		SubjectIssuerBlob.pbData = pbEncoded;

		// Prepare key provider structure for self-signed certificate
		CRYPT_KEY_PROV_INFO KeyProvInfo;
		memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
		KeyProvInfo.pwszContainerName = szContainer;
		KeyProvInfo.pwszProvName = szProvider;
		KeyProvInfo.dwProvType = dwProvType;
		KeyProvInfo.dwFlags = 0;
		KeyProvInfo.cProvParam = 0;
		KeyProvInfo.rgProvParam = NULL;
		KeyProvInfo.dwKeySpec = dwKeySpec;

		// Prepare algorithm structure for self-signed certificate
		CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
		memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
		SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

		// Prepare Expiration date for self-signed certificate
		SYSTEMTIME EndTime;
		GetSystemTime(&EndTime);
		EndTime.wYear += 5;

		// Create self-signed certificate
		//_tprintf(_T(“CertCreateSelfSignCertificate… “));
		pCertContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, 0);
		if (!pCertContext) {
			// Error
			printf("CertCreateSelfSignCertificate Error=0x%x\n", GetLastError());
			return FALSE;
		}

		hStoreOpen = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"My");
		if (!hStoreOpen) {
			// Error
			printf("CertOpenStore Error=0x%x\n", GetLastError());
			return FALSE;
		}

		// Add self-signed cert to the store
		//_tprintf(_T(“CertAddCertificateContextToStore… “));
		CRYPT_DATA_BLOB cryptBlob;
		cryptBlob.cbData = 0;
		cryptBlob.pbData = NULL;
		if (!PFXExportCertStore(hStoreOpen, &cryptBlob, L"", CRYPT_EXPORTABLE)) {
			printf("PFXExportCertStore(1st) Error=0x%x\n", GetLastError());
			return FALSE;
		}
		if (0 == cryptBlob.cbData) {
			printf("cryptBlob.cbData == 0\n");
			return FALSE;
		}
		cryptBlob.pbData = (BYTE *)malloc(cryptBlob.cbData);
		if (!PFXExportCertStore(hStoreOpen, &cryptBlob, L"", CRYPT_EXPORTABLE)) {
			printf("PFXExportCertStore(2nd) Error=0x%x\n", GetLastError());
			return FALSE;
		}
		// is it actually a pfx blob?
		if (!PFXIsPFXBlob(&cryptBlob)) {
			// Error
			printf("PFXIsPFXBlob - cryptBlob is NOT pfx format\n");
			return FALSE;
		}

		DWORD	dwWrote = 0;
		hFile = CreateFile(
			L"exp1cert.pfx",        // name of the write
			GENERIC_WRITE,          // open for writing
			0,                      // do not share
			NULL,                   // default security
			CREATE_NEW,             // create new file only
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);
		if (INVALID_HANDLE_VALUE == hFile) {
			printf("CreateFile Error=0x%x\n", GetLastError());
			return FALSE;
		}

		if (!WriteFile(
			hFile,             // open file handle
			cryptBlob.pbData,  // start of data to write
			cryptBlob.cbData,  // number of bytes to write
			&dwWrote,          // number of bytes that were written
			NULL))
		{
			printf("WriteFile Error=0x%x\n", GetLastError());
			return FALSE;
		}

		if (dwWrote != cryptBlob.cbData) {
			printf("WriteFile Error: dwWrote != cryptBlob.cbData");
			return FALSE;
		}
	}
	__finally {
			// Clean up
			if (!pbEncoded) {
				//_tprintf(_T(“free… “));
				free(pbEncoded);
				//_tprintf(_T(“Success\n”));
			}

			if (hCryptProvOrNCryptKey) {
				//_tprintf(_T(“CryptReleaseContext… “));
				CryptReleaseContext(hCryptProvOrNCryptKey, 0);
				//_tprintf(_T(“Success\n”));
			}

			if (pCertContext) {
				//_tprintf(_T(“CertFreeCertificateContext… “));
				CertFreeCertificateContext(pCertContext);
				//_tprintf(_T(“Success\n”));
			}

			if (hStoreOpen) {
				CertCloseStore(hStoreOpen, 0);
			}
			if (hStorePort) {
				CertCloseStore(hStorePort, 0);
			}
			if (hFile) {
				CloseHandle(hFile);
			}
		}

	return TRUE;
}


int main()
{
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hPubPrivKey = 0;
	HCRYPTKEY hSessionKey = 0;
	BOOL fResult;
	LPBYTE pbKeyMaterial = NULL;

	__try {
		printf("Creating Exponent of One Private Key.\n\n");

		// Create Exponent of One private key
		fResult = CreatePrivateExponentOneKey(MS_ENHANCED_PROV, PROV_RSA_FULL, KEY_CONTAINER_NAME, AT_KEYEXCHANGE, &hProv, &hPubPrivKey);
		if (!fResult) {
			printf("CreatePrivateExponentOneKey failed with %x\n", GetLastError());
			__leave;
		}

		fResult = GenerateSelfSignedCert(MS_ENHANCED_PROV, PROV_RSA_FULL, KEY_CONTAINER_NAME, AT_KEYEXCHANGE);
		if (!fResult) {
			printf("GenerateSelfSignedCert failed with %x\n", GetLastError());
			__leave;
		}
	}
	__finally {
		if (pbKeyMaterial) LocalFree(pbKeyMaterial);
		if (hSessionKey) CryptDestroyKey(hSessionKey);
		if (hPubPrivKey) CryptDestroyKey(hPubPrivKey);
		if (hProv) {
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv, KEY_CONTAINER_NAME, MS_ENHANCED_PROV,
				PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		}
	}

    return 0;
}

