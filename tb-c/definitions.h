/* 
 * Following code copied (with minor changes) from:
 * "SIMON and SPECK Implementation Guide", Ray Beaulieu, Douglas Shors, Jason Smith, Stefan Treatman-Clark, Bryan Weeks, Louis Wingers, June 26 2018
 * https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide.pdf
 * All rights belong to the respective owners.
 *
 */

#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t

#define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r))))
#define ROTL64(x,r) (((x)<<(r)) | (x>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))

// Extra definitions for the specific application -- not in original Implementation Guide
#define N_ROUNDS__64_96   42
#define N_ROUNDS__64_128  44
#define N_ROUNDS__128_128 68
#define N_ROUNDS__128_192 69
#define N_ROUNDS__128_256 72

#define MODE_ENC 0
#define MODE_DEC 1

#endif // DEFINITIONS_H