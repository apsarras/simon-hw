/**
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 * @brief NSA's Simon cipher C implementation for use with SystemVerilog DPI-C testbench
 *
 * @param crypto_mode   Defines whether it's encryption or decryption (MODE_ENC or MODE_DEC, see definitions.h)
 * @param txt_i         Input plaintext (on encryption) or ciphertext (on decryption)
 * @param key_i         Input Key
 * @param txt_o         Output ciphertext (on encryption) or plaintext (on decryption)
 *
 */

#include "svdpi.h"
#include "veriuser.h"

#include "definitions.h"
#include "functions.h"
#include "simon64.h"
#include "simon128.h"

#include "stdio.h"

void dpi_c_run_simon(int crypto_mode, svOpenArrayHandle txt_i, svOpenArrayHandle key_i, svOpenArrayHandle txt_o)
{
    int sz_txt = svSize(txt_i, 1) * 8;
    int sz_key = svSize(key_i, 1) * 8;
    io_printf("[DPI-C] *** INFO *** Detected Simon%0d/%0d -- %s mode.\n", sz_txt, sz_key, crypto_mode == MODE_ENC ? "encryption" : "decryption");
    
    u8 txti_u8[sz_txt/8];
    u8 key_u8[sz_key/8];
    u8 txto_u8[sz_txt/8];
    // -- 1a. Convert Input Text to Byte array ---------------------------------------------------- //
    for (int i=svLow(txt_i, 1); i<(svHigh(txt_i, 1)+1); i++) {
        txti_u8[i] = *((u8*)svGetArrElemPtr(txt_i, i));
    }
    // -- 1b. Convert Key to Byte array ----------------------------------------------------------- //
    for (int i=svLow(key_i, 1); i<(svHigh(key_i, 1)+1); i++)
        key_u8[i] = *((u8*)svGetArrElemPtr(key_i, i));
    
    if (sz_txt == 64) {
        u32 txti_u32[sz_txt/32];
        u32 key_u32[sz_key/32];
        u32 txto_u32[sz_txt/32];
        // -- 2. Convert Plaintext & Key to Words ------------------------------------------------- //
        BytesToWords32(txti_u8, txti_u32, sz_txt/8);
        BytesToWords32(key_u8, key_u32, sz_key/8);
        
        // -- 3. Run Key Schedule & Enc/Decryption ------------------------------------------------ //
        if (sz_key == 96) {
            u32 rk[N_ROUNDS__64_96];
            Simon6496KeySchedule(key_u32, rk);
            if (crypto_mode == MODE_ENC)
                Simon6496Encrypt(txti_u32, txto_u32, rk);
            else
                Simon6496Decrypt(txto_u32, txti_u32, rk);
        } else if (sz_key == 128) {
            u32 rk[N_ROUNDS__64_128];
            Simon64128KeySchedule(key_u32, rk);
            if (crypto_mode == MODE_ENC)
                Simon64128Encrypt(txti_u32, txto_u32, rk);
            else
                Simon64128Decrypt(txto_u32, txti_u32, rk);
        } else {
            // fail
            io_printf("[DPI-C] *** FAILURE *** I dont know how to run Simon%0d/%0d\n", sz_txt, sz_key);
        }
        // -- 4. Convert Output Text to Bytes ----------------------------------------------------- //
        Words32ToBytes(txto_u32, txto_u8, sz_txt/8);
    } else if (sz_txt == 128) {
        u64 txti_u64[sz_txt/64];
        u64 key_u64[sz_key/64];
        u64 txto_u64[sz_txt/64];
        
        // -- 2. Convert Plaintext & Key to Words ------------------------------------------------- //
        BytesToWords64(txti_u8, txti_u64, sz_txt/8);
        BytesToWords64(key_u8, key_u64, sz_key/8);

        // -- 3. Run Key Schedule & Enc/Decryption ------------------------------------------------ //
        if (sz_key == 128) {
            u64 rk[N_ROUNDS__128_128];
            Simon128128KeySchedule(key_u64, rk);
            if (crypto_mode == MODE_ENC)
                Simon128128Encrypt(txti_u64, txto_u64, rk);
            else
                Simon128128Decrypt(txto_u64, txti_u64, rk);
        } else if (sz_key == 192) {
            u64 rk[N_ROUNDS__128_192];
            Simon128192KeySchedule(key_u64, rk);
            if (crypto_mode == MODE_ENC)
                Simon128192Encrypt(txti_u64, txto_u64, rk);
            else
                Simon128192Decrypt(txto_u64, txti_u64, rk);
        } else if (sz_key == 256) {
            u64 rk[N_ROUNDS__128_256];
            Simon128256KeySchedule(key_u64, rk);
            if (crypto_mode == MODE_ENC)
                Simon128256Encrypt(txti_u64, txto_u64, rk);
            else
                Simon128256Decrypt(txto_u64, txti_u64, rk);
        } else {
            // fail
            io_printf("[DPI-C] *** FAILURE *** I dont know how to run Simon%0d/%0d\n", sz_txt, sz_key);
        }
        // -- 4. Convert Output Text to Bytes ---------------------------------------------------00 //
        Words64ToBytes(txto_u64, txto_u8, sz_txt/8);
    } else {
        // fail
        io_printf("[DPI-C] *** FAILURE *** I dont know how to run Simon%0d/%0d\n", sz_txt, sz_key);
    }
    
    // -- 5. Convert Output Text to sv open array ------------------------------------------------- //
    for (int i=svLow(txt_i, 1); i<(svHigh(txt_i, 1)+1); i++)
        *(u8*)svGetArrElemPtr1(txt_o, i) = txto_u8[i];
}
