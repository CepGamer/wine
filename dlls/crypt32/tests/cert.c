/*
 * crypt32 cert functions tests
 *
 * Copyright 2005 Juan Lang
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winerror.h>
#include <wincrypt.h>

#include "wine/test.h"

static void testCryptHashCert(void)
{
    static const BYTE emptyHash[] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b,
     0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07,
     0x09 };
    static const BYTE knownHash[] = { 0xae, 0x9d, 0xbf, 0x6d, 0xf5, 0x46, 0xee,
     0x8b, 0xc5, 0x7a, 0x13, 0xba, 0xc2, 0xb1, 0x04, 0xf2, 0xbf, 0x52, 0xa8,
     0xa2 };
    static const BYTE toHash[] = "abcdefghijklmnopqrstuvwxyz0123456789.,;!?:";
    BOOL ret;
    BYTE hash[20];
    DWORD hashLen = sizeof(hash);

    /* NULL buffer and nonzero length crashes
    ret = CryptHashCertificate(0, 0, 0, NULL, size, hash, &hashLen);
       empty hash length also crashes
    ret = CryptHashCertificate(0, 0, 0, buf, size, hash, NULL);
     */
    /* Test empty hash */
    ret = CryptHashCertificate(0, 0, 0, toHash, sizeof(toHash), NULL,
     &hashLen);
    ok(ret, "CryptHashCertificate failed: %08lx\n", GetLastError());
    ok(hashLen == sizeof(hash),
     "Got unexpected size of hash %ld, expected %d\n", hashLen, sizeof(hash));
    /* Test with empty buffer */
    ret = CryptHashCertificate(0, 0, 0, NULL, 0, hash, &hashLen);
    ok(ret, "CryptHashCertificate failed: %08lx\n", GetLastError());
    ok(!memcmp(hash, emptyHash, sizeof(emptyHash)),
     "Unexpected hash of nothing\n");
    /* Test a known value */
    ret = CryptHashCertificate(0, 0, 0, toHash, sizeof(toHash), hash,
     &hashLen);
    ok(ret, "CryptHashCertificate failed: %08lx\n", GetLastError());
    ok(!memcmp(hash, knownHash, sizeof(knownHash)), "Unexpected hash\n");
}

static const BYTE emptyCert[] = { 0x30, 0x00 };
static const BYTE bigCert[] = "\x30\x7a\x02\x01\x01\x30\x02\x06\x00"
 "\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x13\x0a\x4a\x75\x61\x6e\x20\x4c"
 "\x61\x6e\x67\x00\x30\x22\x18\x0f\x31\x36\x30\x31\x30\x31\x30\x31\x30\x30\x30"
 "\x30\x30\x30\x5a\x18\x0f\x31\x36\x30\x31\x30\x31\x30\x31\x30\x30\x30\x30\x30"
 "\x30\x5a\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x13\x0a\x4a\x75\x61\x6e"
 "\x20\x4c\x61\x6e\x67\x00\x30\x07\x30\x02\x06\x00\x03\x01\x00\xa3\x16\x30\x14"
 "\x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\x30\x06\x01\x01\xff\x02\x01"
 "\x01";
static const BYTE signedBigCert[] = {
 0x30, 0x81, 0x93, 0x30, 0x7a, 0x02, 0x01, 0x01, 0x30, 0x02, 0x06, 0x00, 0x30,
 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a,
 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x22, 0x18, 0x0f,
 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30,
 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06,
 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61,
 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06, 0x00, 0x03, 0x01, 0x00, 0xa3,
 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30, 0x02, 0x06,
 0x00, 0x03, 0x11, 0x00, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
static const BYTE serializedCert[] = { 0x20, 0x00, 0x00, 0x00,
 0x01, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x30, 0x7a, 0x02, 0x01, 0x01,
 0x30, 0x02, 0x06, 0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75, 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67,
 0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x31, 0x36, 0x30, 0x31,
 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15,
 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x4a, 0x75,
 0x61, 0x6e, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x00, 0x30, 0x07, 0x30, 0x02, 0x06,
 0x00, 0x03, 0x01, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02,
 0x01, 0x01 };

static void testMemStore(void)
{
    HCERTSTORE store1, store2;
    PCCERT_CONTEXT context;
    BOOL ret;

    /* NULL provider */
    store1 = CertOpenStore(0, 0, 0, 0, NULL);
    ok(!store1 && GetLastError() == ERROR_FILE_NOT_FOUND,
     "Expected ERROR_FILE_NOT_FOUND, got %ld\n", GetLastError());
    /* weird flags */
    store1 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_DELETE_FLAG, NULL);
    ok(!store1 && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED,
     "Expected ERROR_CALL_NOT_IMPLEMENTED, got %ld\n", GetLastError());

    /* normal */
    store1 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store1 != NULL, "CertOpenStore failed: %ld\n", GetLastError());
    /* open existing doesn't */
    store2 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_OPEN_EXISTING_FLAG, NULL);
    ok(store2 != NULL, "CertOpenStore failed: %ld\n", GetLastError());
    ok(store1 != store2, "Expected different stores\n");

    /* add a bogus (empty) cert */
    context = NULL;
    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING, emptyCert,
     sizeof(emptyCert), CERT_STORE_ADD_ALWAYS, &context);
    /* Windows returns CRYPT_E_ASN1_EOD, but accept CRYPT_E_ASN1_CORRUPT as
     * well (because matching errors is tough in this case)
     */
    ok(!ret && (GetLastError() == CRYPT_E_ASN1_EOD || GetLastError() ==
     CRYPT_E_ASN1_CORRUPT),
     "Expected CRYPT_E_ASN1_EOD or CRYPT_E_ASN1_CORRUPT, got %08lx\n",
     GetLastError());
    /* add a signed cert (this also fails) */
    ok(!ret && (GetLastError() == CRYPT_E_ASN1_EOD || GetLastError() ==
     CRYPT_E_ASN1_CORRUPT),
     "Expected CRYPT_E_ASN1_EOD or CRYPT_E_ASN1_CORRUPT, got %08lx\n",
     GetLastError());
    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING,
     signedBigCert, sizeof(signedBigCert) - 1, CERT_STORE_ADD_ALWAYS, &context);
    /* add a cert to store1 */
    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING, bigCert,
     sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    ok(context != NULL, "Expected a valid cert context\n");
    if (context)
    {
        DWORD size;
        BYTE *buf;

        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected cert of %d bytes, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, sizeof(bigCert) - 1),
         "Unexpected encoded cert in context\n");
        ok(context->hCertStore == store1, "Unexpected store\n");

        /* check serializing this element */
        /* These crash
        ret = CertSerializeCertificateStoreElement(NULL, 0, NULL, NULL);
        ret = CertSerializeCertificateStoreElement(context, 0, NULL, NULL);
        ret = CertSerializeCertificateStoreElement(NULL, 0, NULL, &size);
         */
        /* apparently flags are ignored */
        ret = CertSerializeCertificateStoreElement(context, 1, NULL, &size);
        ok(ret, "CertSerializeCertificateStoreElement failed: %08lx\n",
         GetLastError());
        buf = HeapAlloc(GetProcessHeap(), 0, size);
        if (buf)
        {
            ret = CertSerializeCertificateStoreElement(context, 0, buf, &size);
            ok(size == sizeof(serializedCert), "Expected size %d, got %ld\n",
             sizeof(serializedCert), size);
            ok(!memcmp(serializedCert, buf, size),
             "Unexpected serialized cert\n");
            HeapFree(GetProcessHeap(), 0, buf);
        }

        ret = CertFreeCertificateContext(context);
        ok(ret, "CertFreeCertificateContext failed: %08lx\n", GetLastError());
    }
    /* verify the cert's in store1 */
    context = CertEnumCertificatesInStore(store1, NULL);
    ok(context != NULL, "Expected a valid context\n");
    context = CertEnumCertificatesInStore(store1, context);
    ok(!context && GetLastError() == CRYPT_E_NOT_FOUND,
     "Expected CRYPT_E_NOT_FOUND, got %08lx\n", GetLastError());
    /* verify store2 (the "open existing" mem store) is still empty */
    context = CertEnumCertificatesInStore(store2, NULL);
    ok(!context, "Expected an empty store\n");
    /* delete the cert from store1, and check it's empty */
    context = CertEnumCertificatesInStore(store1, NULL);
    if (context)
    {
        /* Deleting a bitwise copy crashes with an access to an uninitialized
         * pointer, so a cert context has some special data out there in memory
         * someplace
        CERT_CONTEXT copy;
        memcpy(&copy, context, sizeof(copy));
        ret = CertDeleteCertificateFromStore(&copy);
         */
        PCCERT_CONTEXT copy = CertDuplicateCertificateContext(context);

        ok(copy != NULL, "CertDuplicateCertificateContext failed: %08lx\n",
         GetLastError());
        ret = CertDeleteCertificateFromStore(context);
        ok(ret, "CertDeleteCertificateFromStore failed: %08lx\n",
         GetLastError());
        /* try deleting a copy */
        ret = CertDeleteCertificateFromStore(copy);
        ok(ret, "CertDeleteCertificateFromStore failed: %08lx\n",
         GetLastError());
        /* check that the store is empty */
        context = CertEnumCertificatesInStore(store1, NULL);
        ok(!context, "Expected an empty store\n");
    }

    /* close an empty store */
    ret = CertCloseStore(NULL, 0);
    ok(ret, "CertCloseStore failed: %ld\n", GetLastError());
    ret = CertCloseStore(store1, 0);
    ok(ret, "CertCloseStore failed: %ld\n", GetLastError());
    ret = CertCloseStore(store2, 0);
    ok(ret, "CertCloseStore failed: %ld\n", GetLastError());

    /* This seems nonsensical, but you can open a read-only mem store, only
     * it isn't read-only
     */
    store1 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_READONLY_FLAG, NULL);
    ok(store1 != NULL, "CertOpenStore failed: %ld\n", GetLastError());
    /* yep, this succeeds */
    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING, bigCert,
     sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, &context);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    ok(context != NULL, "Expected a valid cert context\n");
    if (context)
    {
        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected cert of %d bytes, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, sizeof(bigCert) - 1),
         "Unexpected encoded cert in context\n");
        ok(context->hCertStore == store1, "Unexpected store\n");
        ret = CertDeleteCertificateFromStore(context);
        ok(ret, "CertDeleteCertificateFromStore failed: %08lx\n",
         GetLastError());
    }
    CertCloseStore(store1, 0);
}

static const BYTE bigCert2[] = "\x30\x7a\x02\x01\x01\x30\x02\x06\x00"
 "\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x13\x0a\x41\x6c\x65\x78\x20\x4c"
 "\x61\x6e\x67\x00\x30\x22\x18\x0f\x31\x36\x30\x31\x30\x31\x30\x31\x30\x30\x30"
 "\x30\x30\x30\x5a\x18\x0f\x31\x36\x30\x31\x30\x31\x30\x31\x30\x30\x30\x30\x30"
 "\x30\x5a\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x13\x0a\x41\x6c\x65\x78"
 "\x20\x4c\x61\x6e\x67\x00\x30\x07\x30\x02\x06\x00\x03\x01\x00\xa3\x16\x30\x14"
 "\x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\x30\x06\x01\x01\xff\x02\x01"
 "\x01";

static void testCollectionStore(void)
{
    HCERTSTORE store1, store2, collection, collection2;
    PCCERT_CONTEXT context;
    BOOL ret;

    collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);

    /* Try adding a cert to any empty collection */
    ret = CertAddEncodedCertificateToStore(collection, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(!ret && GetLastError() == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED),
     "Expected HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED), got %08lx\n",
     GetLastError());

    /* Create and add a cert to a memory store */
    store1 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    /* Add the memory store to the collection, without allowing adding */
    ret = CertAddStoreToCollection(collection, store1, 0, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());
    /* Verify the cert is in the collection */
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == collection, "Unexpected store\n");
        CertFreeCertificateContext(context);
    }
    /* Check that adding to the collection isn't allowed */
    ret = CertAddEncodedCertificateToStore(collection, X509_ASN_ENCODING,
     bigCert2, sizeof(bigCert2) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(!ret && GetLastError() == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED),
     "Expected HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED), got %08lx\n",
     GetLastError());

    /* Create a new memory store */
    store2 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    /* Try adding a store to a non-collection store */
    ret = CertAddStoreToCollection(store1, store2,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(!ret && GetLastError() == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),
     "Expected HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER), got %08lx\n",
     GetLastError());
    /* Try adding some bogus stores */
    /* This crashes in Windows
    ret = CertAddStoreToCollection(0, store2,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
     */
    /* This "succeeds"... */
    ret = CertAddStoreToCollection(collection, 0,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());
    /* while this crashes.
    ret = CertAddStoreToCollection(collection, 1,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
     */

    /* Add it to the collection, this time allowing adding */
    ret = CertAddStoreToCollection(collection, store2,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());
    /* Check that adding to the collection is allowed */
    ret = CertAddEncodedCertificateToStore(collection, X509_ASN_ENCODING,
     bigCert2, sizeof(bigCert2) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    /* Now check that it was actually added to store2 */
    context = CertEnumCertificatesInStore(store2, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == store2, "Unexpected store\n");
        CertFreeCertificateContext(context);
    }
    /* Check that the collection has both bigCert and bigCert2.  bigCert comes
     * first because store1 was added first.
     */
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == collection, "Unexpected store\n");
        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
         "Unexpected cert\n");
        context = CertEnumCertificatesInStore(collection, context);
        ok(context != NULL, "Expected a valid context\n");
        if (context)
        {
            ok(context->hCertStore == collection, "Unexpected store\n");
            ok(context->cbCertEncoded == sizeof(bigCert2) - 1,
             "Expected size %d, got %ld\n", sizeof(bigCert2) - 1,
             context->cbCertEncoded);
            ok(!memcmp(context->pbCertEncoded, bigCert2,
             context->cbCertEncoded), "Unexpected cert\n");
            context = CertEnumCertificatesInStore(collection, context);
            ok(!context, "Unexpected cert\n");
        }
    }
    /* close store2, and check that the collection is unmodified */
    CertCloseStore(store2, 0);
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == collection, "Unexpected store\n");
        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
         "Unexpected cert\n");
        context = CertEnumCertificatesInStore(collection, context);
        ok(context != NULL, "Expected a valid context\n");
        if (context)
        {
            ok(context->hCertStore == collection, "Unexpected store\n");
            ok(context->cbCertEncoded == sizeof(bigCert2) - 1,
             "Expected size %d, got %ld\n", sizeof(bigCert2) - 1,
             context->cbCertEncoded);
            ok(!memcmp(context->pbCertEncoded, bigCert2,
             context->cbCertEncoded), "Unexpected cert\n");
            context = CertEnumCertificatesInStore(collection, context);
            ok(!context, "Unexpected cert\n");
        }
    }

    /* Adding a collection to a collection is legal */
    collection2 = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ret = CertAddStoreToCollection(collection2, collection,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());
    /* check the contents of collection2 */
    context = CertEnumCertificatesInStore(collection2, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == collection2, "Unexpected store\n");
        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
         "Unexpected cert\n");
        context = CertEnumCertificatesInStore(collection2, context);
        ok(context != NULL, "Expected a valid context\n");
        if (context)
        {
            ok(context->hCertStore == collection2, "Unexpected store\n");
            ok(context->cbCertEncoded == sizeof(bigCert2) - 1,
             "Expected size %d, got %ld\n", sizeof(bigCert2) - 1,
             context->cbCertEncoded);
            ok(!memcmp(context->pbCertEncoded, bigCert2,
             context->cbCertEncoded), "Unexpected cert\n");
            context = CertEnumCertificatesInStore(collection2, context);
            ok(!context, "Unexpected cert\n");
        }
    }

    /* I'd like to test closing the collection in the middle of enumeration,
     * but my tests have been inconsistent.  The first time calling
     * CertEnumCertificatesInStore on a closed collection succeeded, while the
     * second crashed.  So anything appears to be fair game.
     * I'd also like to test removing a store from a collection in the middle
     * of an enumeration, but my tests in Windows have been inconclusive.
     * In one scenario it worked.  In another scenario, about a third of the
     * time this leads to "random" crashes elsewhere in the code.  This
     * probably means this is not allowed.
     */

    CertCloseStore(store1, 0);
    CertCloseStore(collection, 0);
    CertCloseStore(collection2, 0);

    /* Add the same cert to two memory stores, then put them in a collection */
    store1 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store1 != 0, "CertOpenStore failed: %08lx\n", GetLastError());
    store2 = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(store2 != 0, "CertOpenStore failed: %08lx\n", GetLastError());

    ret = CertAddEncodedCertificateToStore(store1, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    ret = CertAddEncodedCertificateToStore(store2, X509_ASN_ENCODING,
     bigCert, sizeof(bigCert) - 1, CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: %08lx\n", GetLastError());
    collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(collection != 0, "CertOpenStore failed: %08lx\n", GetLastError());

    ret = CertAddStoreToCollection(collection, store1,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());
    ret = CertAddStoreToCollection(collection, store2,
     CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    ok(ret, "CertAddStoreToCollection failed: %08lx\n", GetLastError());

    /* Check that the collection has two copies of the same cert */
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        ok(context->hCertStore == collection, "Unexpected store\n");
        ok(context->cbCertEncoded == sizeof(bigCert) - 1,
         "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
         context->cbCertEncoded);
        ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
         "Unexpected cert\n");
        context = CertEnumCertificatesInStore(collection, context);
        ok(context != NULL, "Expected a valid context\n");
        if (context)
        {
            ok(context->hCertStore == collection, "Unexpected store\n");
            ok(context->cbCertEncoded == sizeof(bigCert) - 1,
             "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
             context->cbCertEncoded);
            ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
             "Unexpected cert\n");
            context = CertEnumCertificatesInStore(collection, context);
            ok(context == NULL, "Unexpected cert\n");
        }
    }

    /* The following would check whether I can delete an identical cert, rather
     * than one enumerated from the store.  It crashes, so that means I must
     * only call CertDeleteCertificateFromStore with contexts enumerated from
     * the store.
    context = CertCreateCertificateContext(X509_ASN_ENCODING, bigCert,
     sizeof(bigCert) - 1);
    ok(context != NULL, "CertCreateCertificateContext failed: %08lx\n",
     GetLastError());
    if (context)
    {
        ret = CertDeleteCertificateFromStore(collection, context);
        printf("ret is %d, GetLastError is %08lx\n", ret, GetLastError());
        CertFreeCertificateContext(context);
    }
     */

    /* Now check deleting from the collection. */
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(context != NULL, "Expected a valid context\n");
    if (context)
    {
        CertDeleteCertificateFromStore(context);
        /* store1 should now be empty */
        context = CertEnumCertificatesInStore(store1, NULL);
        ok(!context, "Unexpected cert\n");
        /* and there should be one certificate in the collection */
        context = CertEnumCertificatesInStore(collection, NULL);
        ok(context != NULL, "Expected a valid cert\n");
        if (context)
        {
            ok(context->hCertStore == collection, "Unexpected store\n");
            ok(context->cbCertEncoded == sizeof(bigCert) - 1,
             "Expected size %d, got %ld\n", sizeof(bigCert) - 1,
             context->cbCertEncoded);
            ok(!memcmp(context->pbCertEncoded, bigCert, context->cbCertEncoded),
             "Unexpected cert\n");
        }
        context = CertEnumCertificatesInStore(collection, context);
        ok(context == NULL, "Unexpected cert\n");
    }

    /* Finally, test removing stores from the collection.  No return value, so
     * it's a bit funny to test.
     */
    /* This crashes
    CertRemoveStoreFromCollection(NULL, NULL);
     */
    /* This "succeeds," no crash, no last error set */
    SetLastError(0xdeadbeef);
    CertRemoveStoreFromCollection(store2, collection);
    ok(GetLastError() == 0xdeadbeef,
     "Didn't expect an error to be set: %08lx\n", GetLastError());

    /* After removing store2, the collection should be empty */
    SetLastError(0xdeadbeef);
    CertRemoveStoreFromCollection(collection, store2);
    ok(GetLastError() == 0xdeadbeef,
     "Didn't expect an error to be set: %08lx\n", GetLastError());
    context = CertEnumCertificatesInStore(collection, NULL);
    ok(!context, "Unexpected cert\n");

    CertCloseStore(collection, 0);
    CertCloseStore(store2, 0);
    CertCloseStore(store1, 0);
}

static void testCertProperties(void)
{
    PCCERT_CONTEXT context = CertCreateCertificateContext(X509_ASN_ENCODING,
     bigCert, sizeof(bigCert) - 1);

    ok(context != NULL, "CertCreateCertificateContext failed: %08lx\n",
     GetLastError());
    if (context)
    {
        DWORD propID, numProps, access, size;
        BOOL ret;
        BYTE hash[20] = { 0 }, hashProperty[20];
        CRYPT_DATA_BLOB blob;

        /* This crashes
        propID = CertEnumCertificateContextProperties(NULL, 0);
         */

        propID = 0;
        numProps = 0;
        do {
            propID = CertEnumCertificateContextProperties(context, propID);
            if (propID)
                numProps++;
        } while (propID != 0);
        ok(numProps == 0, "Expected 0 properties, got %ld\n", numProps);

        /* Tests with a NULL cert context.  Prop ID 0 fails.. */
        ret = CertSetCertificateContextProperty(NULL, 0, 0, NULL);
        ok(!ret && GetLastError() ==
         HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),
         "Expected HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER), got %08lx\n",
         GetLastError());
        /* while this just crashes.
        ret = CertSetCertificateContextProperty(NULL,
         CERT_KEY_PROV_HANDLE_PROP_ID, 0, NULL);
         */

        ret = CertSetCertificateContextProperty(context, 0, 0, NULL);
        ok(!ret && GetLastError() ==
         HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),
         "Expected HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER), got %08lx\n",
         GetLastError());
        /* Can't set the cert property directly, this crashes.
        ret = CertSetCertificateContextProperty(context,
         CERT_CERT_PROP_ID, 0, bigCert2);
         */

        /* This crashes.
        ret = CertGetCertificateContextProperty(context,
         CERT_ACCESS_STATE_PROP_ID, 0, NULL);
         */
        size = sizeof(access);
        ret = CertGetCertificateContextProperty(context,
         CERT_ACCESS_STATE_PROP_ID, &access, &size);
        ok(ret, "CertGetCertificateContextProperty failed: %08lx\n",
         GetLastError());
        ok(!(access & CERT_ACCESS_STATE_WRITE_PERSIST_FLAG),
         "Didn't expect a persisted cert\n");
        /* Trying to set this "read only" property crashes.
        access |= CERT_ACCESS_STATE_WRITE_PERSIST_FLAG;
        ret = CertSetCertificateContextProperty(context,
         CERT_ACCESS_STATE_PROP_ID, 0, &access);
         */

        /* Can I set the hash to an invalid hash? */
        blob.pbData = hash;
        blob.cbData = sizeof(hash);
        ret = CertSetCertificateContextProperty(context, CERT_HASH_PROP_ID, 0,
         &blob);
        ok(ret, "CertSetCertificateContextProperty failed: %08lx\n",
         GetLastError());
        size = sizeof(hashProperty);
        ret = CertGetCertificateContextProperty(context, CERT_HASH_PROP_ID,
         hashProperty, &size);
        ok(!memcmp(hashProperty, hash, sizeof(hash)), "Unexpected hash\n");
        /* Delete the (bogus) hash, and get the real one */
        ret = CertSetCertificateContextProperty(context, CERT_HASH_PROP_ID, 0,
         NULL);
        ok(ret, "CertSetCertificateContextProperty failed: %08lx\n",
         GetLastError());
        size = sizeof(hash);
        ret = CryptHashCertificate(0, 0, 0, bigCert, sizeof(bigCert) - 1,
         hash, &size);
        ok(ret, "CryptHashCertificate failed: %08lx\n", GetLastError());
        ret = CertGetCertificateContextProperty(context, CERT_HASH_PROP_ID,
         hashProperty, &size);
        ok(ret, "CertGetCertificateContextProperty failed: %08lx\n",
         GetLastError());
        ok(!memcmp(hash, hashProperty, sizeof(hash)), "Unexpected hash\n");

        /* Now that the hash property is set, we should get one property when
         * enumerating.
         */
        propID = 0;
        numProps = 0;
        do {
            propID = CertEnumCertificateContextProperties(context, propID);
            if (propID)
                numProps++;
        } while (propID != 0);
        ok(numProps == 1, "Expected 1 properties, got %ld\n", numProps);

        CertFreeCertificateContext(context);
    }
}

START_TEST(cert)
{
    testCryptHashCert();

    /* various combinations of CertOpenStore */
    testMemStore();
    testCollectionStore();

    testCertProperties();
}
