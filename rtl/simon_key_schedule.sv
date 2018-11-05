/**
 * @info NSA's Simon key schedule algorithm (combinational logic)
 *
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 * @brief Simon generic implementation with a fixed number of keywords m and word size m [ref]
 *        [ref] R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers, "The Simon and Speck Families of Lightweight Block Ciphers", DAC 2015
 *        Depending on the WW and NKW parameters (n and m resp. in [ref]), a different Simon configuration is instantiated.
 *        The following table [ref] summarizes the resulting configuration based on the input params:
 *
 *              -------------------------------------------------------
 *             |  block  |   key   |  word  |   key   | const | rounds |
 *             | size 2n | size mn | size n | words m |  seq  |   T    |
 *             |-------------------------------------------------------|
 *             |   32    |   64    |   16   |    4    |   z0  |  32    |
 *             |-------------------------------------------------------|
 *             |   48    |   72    |   24   |    3    |   z0  |  36    |
 *             |         |   96    |        |    4    |   z1  |  36    |
 *             |-------------------------------------------------------|
 *             |   64    |   96    |   32   |    3    |   z2  |  42    |
 *             |         |   128   |        |    4    |   z3  |  44    |
 *             |-------------------------------------------------------|
 *             |   96    |   96    |   48   |    2    |   z2  |  52    |
 *             |         |   144   |        |    3    |   z3  |  54    |
 *             |-------------------------------------------------------|
 *             |   128   |   128   |   64   |    2    |   z2  |  68    |
 *             |         |   192   |        |    3    |   z3  |  69    |
 *             |         |   256   |        |    4    |   z4  |  72    |
 *              -------------------------------------------------------
 *
 * @param WW        Defines the word size (n in [ref])
 * @param NKW       Defines the number of key words (m in [ref]).
 */

module simon_key_schedule
#(
    parameter int WW    = 16, // WW: Word Width (n) -- Legal values: see 'n' in above table
    parameter int NKW   = 4   // NKW: Number of Key Words (m) -- Legal values: see 'm' in above table
)
(
    input  logic                    mode_i,     // 0 for encryption, 1 for decryption
    input  logic[NKW-1:0][WW-1:0]   key_cur_i,  // key word inputs
    input  logic[WW-1:0]            c_xor_z_i,  // xor'ed outside
    
    output logic[NKW-1:0][WW-1:0]   key_nxt_o   // key word inputs
);

// -- Right Rotation handy function --------------------------------------------------------------- //
function logic[WW-1:0] rot_right(input logic[WW-1:0] a, input int n);
    return (a >> n) | (a << (WW-n));
endfunction

// -- Comb Logic ---------------------------------------------------------------------------------- //
logic[WW-1:0] xor_all; // all XORs in the function
// Depending on the number of key words (m), a different functionality is performed
if (NKW == 2) begin: g_if_m_eq_2
    logic[WW-1:0] k1_rr3;
    assign k1_rr3 = rot_right(key_cur_i[1], 3);
    assign xor_all = k1_rr3 ^ key_cur_i[0] ^ rot_right(k1_rr3, 1) ^ c_xor_z_i;
end else if (NKW == 3) begin: g_if_m_eq_3
    logic[WW-1:0] key_to_rot;
    logic[WW-1:0] k_rr3;
    // MUX key for calculations (i-2 for encryption, i-1 for decryption)
    assign key_to_rot   = ({WW{~mode_i}} & key_cur_i[2]) | 
                          ({WW{ mode_i}} & key_cur_i[1]);
    assign k_rr3        = rot_right(key_to_rot, 3);
    assign xor_all      = k_rr3 ^ key_cur_i[0] ^ rot_right(k_rr3, 1) ^ c_xor_z_i;
end else if (NKW == 4) begin: g_if_m_eq_4
    logic[WW-1:0] key_to_rot;
    logic[WW-1:0] key_to_xor;
    logic[WW-1:0] k_rr3;
    logic[WW-1:0] k_rr3_xor_k1;
    assign key_to_rot       = ({WW{~mode_i}} & key_cur_i[3]) |
                              ({WW{ mode_i}} & key_cur_i[1]);
    assign key_to_xor       = ({WW{~mode_i}} & key_cur_i[1]) |
                              ({WW{ mode_i}} & key_cur_i[3]);
    assign k_rr3            = rot_right(key_to_rot, 3);
    assign k_rr3_xor_k1     = k_rr3 ^ key_to_xor;
    assign xor_all          = k_rr3_xor_k1 ^ key_cur_i[0] ^ rot_right(k_rr3_xor_k1, 1) ^ c_xor_z_i;
end

// -- Outputs ------------------------------------------------------------------------------------- //
for (genvar i=0; i<(NKW-1); i++) begin: g_for_i
    assign key_nxt_o[i] = key_cur_i[i+1];
end
assign key_nxt_o[NKW-1] = xor_all;

// -- Design Parameter Assertions ----------------------------------------------------------------- //
// synthesis translate_off
initial begin
    #0 assert (WW inside {16, 24, 32, 48, 64}) else $error("Illegal WW parameter value %0d -- legal values: 16, 24, 32, 48, 64", WW);
    
    if (WW == 16)
        #0 assert (NKW == 4) else $error("Illegal NKW parameter value %0d -- legal values for WW = %0d: 4", NKW, WW);
    else if ((WW == 24) || (WW == 32))
        #0 assert (NKW inside {3, 4}) else $error("Illegal NKW parameter value %0d -- legal values for WW = %0d: 3, 4", NKW, WW);
    else if (WW == 48)
        #0 assert (NKW inside {2, 3}) else $error("Illegal NKW parameter value %0d -- legal values for WW = %0d: 2, 3", NKW, WW);
    else if (WW == 64)
        #0 assert (NKW inside {2, 3, 4}) else $error("Illegal NKW parameter value %0d -- legal values for WW = %0d: 2, 3, 4", NKW, WW);
end
// synthesis translate_on

endmodule
