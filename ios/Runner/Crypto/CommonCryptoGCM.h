//
//  CommonCryptoGCM.h
//  Sero
//
//  Redeclares Apple's CommonCrypto incremental GCM SPI so it can be called
//  from Swift for constant-memory, chunk-by-chunk AES-256-GCM streaming.
//  These symbols ship inside CommonCrypto on every iOS/macOS release since
//  iOS 11 / macOS 10.13; only the *declarations* are missing from the public
//  umbrella header, not the implementation. No third-party or OpenSSL code
//  is involved - this is exclusively Apple's own CommonCrypto library.
//
#ifndef CommonCryptoGCM_h
#define CommonCryptoGCM_h

#include <CommonCrypto/CommonCrypto.h>

CCCryptorStatus CCCryptorGCMSetIV(CCCryptorRef cryptorRef,
                                   const void *iv,
                                   size_t ivLen);

CCCryptorStatus CCCryptorGCMAddAAD(CCCryptorRef cryptorRef,
                                    const void *aData,
                                    size_t aDataLen);

CCCryptorStatus CCCryptorGCMEncrypt(CCCryptorRef cryptorRef,
                                     const void *dataIn,
                                     size_t dataInLength,
                                     void *dataOut);

CCCryptorStatus CCCryptorGCMDecrypt(CCCryptorRef cryptorRef,
                                     const void *dataIn,
                                     size_t dataInLength,
                                     void *dataOut);

/* iOS 11+ non-deprecated finalize: writes the 16-byte authentication tag. */
CCCryptorStatus CCCryptorGCMFinalize(CCCryptorRef cryptorRef,
                                      void *tagOut,
                                      size_t tagLength);

CCCryptorStatus CCCryptorGCMReset(CCCryptorRef cryptorRef);

#endif /* CommonCryptoGCM_h */
