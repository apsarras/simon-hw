/**
 * @info TB item for SIMON top module
 *
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 */

package tb_crypto_item_pkg;

import simon_const_pkg::*;

// -- Item for performance measurements ------------------------------------------------------- //
class crypto_item
#(
    parameter int   WW          = 16,
    parameter int   NKW         = 4
);

time        gen_time;
time        sink_time;
rand bit    crypto_mode; // 0 for encrypt, 1 for decrypt
rand byte   txt[2*WW/8]; // Plaintext for Enryption -- Ciphertext for decryption
rand byte   key[NKW*WW/8];

// empty constructor
function new();
endfunction

// Hard Copy
function void hard_copy(ref crypto_item #(.WW(WW), .NKW(NKW)) item_cpy);
    item_cpy = new();
    item_cpy.crypto_mode = this.crypto_mode;
    item_cpy.txt = this.txt;
    item_cpy.key = this.key;
    item_cpy.gen_time = this.gen_time;
    item_cpy.sink_time = this.sink_time;
endfunction

// Human-Readable string
function string to_str(logic txt_is_pt);
    string enc_dec_str;
    string pt_ct_str;
    enc_dec_str = this.crypto_mode == MODE_ENC ? "enc" : "dec";
    pt_ct_str = txt_is_pt ? "pt" : "ct";
    
    return $sformatf("%s | %s: %s | key: %s", enc_dec_str, pt_ct_str, this.txt_to_str(), this.key_to_str());
endfunction

// Text setter using packed array of words as input
function void set_txt_from_packed_words(bit[2-1:0][WW-1:0] txt_in);
    for (int w=0; w<2; w++)
        for (int b=0; b<WW/8; b++)
            this.txt[w*WW/8 + b] = txt_in[w][b*8 +: 8];
endfunction

// Key setter using packed array of words as input
function void set_key_from_packed_words(bit[NKW-1:0][WW-1:0] key_in);
    for (int w=0; w<NKW; w++)
        for (int b=0; b<WW/8; b++)
            this.key[w*WW/8 + b] = key_in[w][b*8 +: 8];
endfunction

// Text getter returning packed array of words
function bit[2-1:0][WW-1:0] get_word_packed_txt();
    bit[2-1:0][WW-1:0] txt_out;
    for (int w=0; w<2; w++)
        for (int b=0; b<WW/8; b++)
            txt_out[w][b*8 +: 8] = this.txt[w*WW/8 + b];
    return txt_out;
endfunction

// Key getter returning packed array of words
function bit[NKW-1:0][WW-1:0] get_word_packed_key();
    bit[NKW-1:0][WW-1:0] key_out;
    for (int w=0; w<NKW; w++)
        for (int b=0; b<WW/8; b++)
            key_out[w][b*8 +: 8] = this.key[w*WW/8 + b];
    return key_out;
endfunction

// Method for getting "flattened" version of the Plaintext
function bit[2*WW-1:0] get_flattened_txt();
    bit[2*WW-1:0] txt_out;
    for (int b=0; b<2*WW/8; b++)
        txt_out[b*8 +: 8] = this.txt[b];
    return txt_out;
endfunction

// Method for getting "flattened" version of the Key
function bit[NKW*WW-1:0] get_flattened_key();
    bit[NKW*WW-1:0] key_out;
    for (int b=0; b<NKW*WW/8; b++)
        key_out[b*8 +: 8] = this.key[b];
    return key_out;
endfunction


// Method returning human-readable key
function string key_to_str();
    string str_ret;
    str_ret = "";
    for (int b=0; b<NKW*WW/8; b++)
        str_ret = {str_ret, $sformatf("%2h ", this.key[b])};
    return str_ret;
endfunction

// Method returning human-readable text
function string txt_to_str();
    string str_ret;
    str_ret = "";
    for (int b=0; b<2*WW/8; b++)
        str_ret = {str_ret, $sformatf("%2h ", this.txt[b])};
    return str_ret;
endfunction

endclass

endpackage
