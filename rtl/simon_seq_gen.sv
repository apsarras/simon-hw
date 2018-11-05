/**
 * @info NSA's Simon sequence generator
 *
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 * @brief Produces z_j sequence using an LFSR for u/v/w vectors and a Flip Flop for the t sequence
 *        Part of simon generic implementation with a fixed number of keywords m and word size m [ref]
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

module simon_seq_gen
#(
    parameter int WW    = 16, // WW: Word Width (n) -- Legal values: see 'n' in above table
    parameter int NKW   = 4   // NKW: Number of Key Words (m) -- Legal values: see 'm' in above table
)
(
    input  logic                clk,        // clock, @posedge
    input  logic                arst_n,     // async reset -- active low
    
    input  logic                mode_i,     // 0 for encrypt, 1 for decrypt
    
    input  logic                rst_seqs_i, // resets sequences
    input  logic                run_en_i,   // should be set to '1' when the algo is running (enables lfsr etc)
    
    output logic                seq_o       // output sequence
);
// -- UNVERIFIED CONFIGS -- //
initial begin
    #0 assert (WW inside {32, 64}) else $error("ONLY WW=32, 64 have been verified using official NSA code! PROCEED AT YOUR OWN RISK");
end
// -- UNVERIFIED CONFIGS -- //

// -- Module Self-Configuration ------------------------------------------------------------------- //
localparam int                              LFSR_N          = 5;
localparam int                              LFSR_C          = 2;
// U, V, R & their reverse
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_U   = '{5'b01000, 5'b00100, 5'b10010, 5'b00001, 5'b10001};
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_V   = '{5'b01100, 5'b00100, 5'b10010, 5'b00001, 5'b10000};
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_W   = '{5'b01000, 5'b00100, 5'b10010, 5'b00001, 5'b10000};
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_UR  = '{5'b00011, 5'b10000, 5'b01000, 5'b00111, 5'b00010};
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_VR  = '{5'b00001, 5'b11000, 5'b01000, 5'b00101, 5'b00010};
localparam logic[0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRIX_WR  = '{5'b00001, 5'b10000, 5'b01000, 5'b00101, 5'b00010};
// Starting LFSR sequences
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_ENC            = 5'b10000;
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_32_64      = 5'b01011; // <-- UNVERIFIED
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_48_72      = 5'b10001; // <-- UNVERIFIED
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_48_96      = 5'b10000; // <-- UNVERIFIED
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_64_96      = 5'b00011;
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_64_128     = 5'b11101;
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_96_96      = 5'b11000; // <-- UNVERIFIED
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_96_144     = 5'b10011; // <-- UNVERIFIED
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_128_128    = 5'b10111;
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_128_192    = 5'b01101;
localparam logic[LFSR_N-1:0]                LFSR_SEQ_RST_DEC_128_256    = 5'b10010;

// Number of rounds (used for T sequence reset value)
localparam logic T_SEQ_RST_ENC                              = 1'b0;
// localparam logic T_SEQ_RST_DEC_32_64                        = 1'bx; // <-- no t sequence for 32/64
// localparam logic T_SEQ_RST_DEC_48_72                        = 1'bx; // <-- no t sequence for 48/72
// localparam logic T_SEQ_RST_DEC_48_96                        = 1'bx; // <-- no t sequence for 48/96
localparam logic T_SEQ_RST_DEC_96_96                        = 1'b1; // <-- UNVERIFIED
localparam logic T_SEQ_RST_DEC_96_144                       = 1'b0; // <-- UNVERIFIED
localparam logic T_SEQ_RST_DEC_64_96                        = 1'b0;
localparam logic T_SEQ_RST_DEC_64_128                       = 1'b1;
localparam logic T_SEQ_RST_DEC_128_128                      = 1'b1;
localparam logic T_SEQ_RST_DEC_128_192                      = 1'b1;
localparam logic T_SEQ_RST_DEC_128_256                      = 1'b1;
// ------------------------------------------------------------------------------------------------ //
// Determine whether an LFSR for the corresponding vector (U, V, W) will be instantiated.
// This depends on the z sequence that will be required for the specific config:
//   z0 = u / z1 = v / z2 = u^t / z3 = v^t / z4 = w^t (where t is period-2 sequence t = 010101...)
// since a different z sequence is used depending on the configuration:
//   z0 (16,4), (24,3)
//   z1 (24,4)
//   z2 (32,3), (48,2), (64,2)
//   z3 (32,4), (48,3), (64,3)
//   z4 (64,4)
// The generated LFSR will depend on the (n,m) [i.e. (WW, NKW)] pairs as follows:
// So, U LFSR --> z0 or z2 --> (16,4), (24,3), (32,3), (48,2), (64,2)
//     V LFSR --> z1 or z3 --> (24,4), (32,4), (48,3), (64,3)
//     W LFSR --> z4       --> (64,4)
localparam int                              Z_SEQ       = (WW == 16 && NKW == 4) || (WW == 24 && NKW == 3)                           ? 0 :
                                                          (WW == 24 && NKW == 4)                                                     ? 1 :
                                                          (WW == 32 && NKW == 3) || (WW == 48 && NKW == 2) || (WW == 64 && NKW == 2) ? 2 :
                                                          (WW == 32 && NKW == 4) || (WW == 48 && NKW == 3) || (WW == 64 && NKW == 3) ? 3 :
                                                                                                                                       4;
localparam logic                            GEN_LFSR_U  = Z_SEQ == 0 || Z_SEQ == 2;
localparam logic                            GEN_LFSR_V  = Z_SEQ == 1 || Z_SEQ == 3;
localparam logic                            GEN_LFSR_W  = Z_SEQ == 4;
// ------------------------------------------------------------------------------------------------ //
localparam logic[LFSR_C-1:0][0:LFSR_N-1][0:LFSR_N-1]    LFSR_MATRICES   = GEN_LFSR_U ? '{LFSR_MATRIX_UR, LFSR_MATRIX_U} :
                                                                          GEN_LFSR_V ? '{LFSR_MATRIX_VR, LFSR_MATRIX_V} :
                                                                                       '{LFSR_MATRIX_WR, LFSR_MATRIX_W};
localparam logic[LFSR_C-1:0][LFSR_N-1:0]                LFSR_SEQ_RSTS   = (WW == 16) && (NKW == 2) ? {LFSR_SEQ_RST_DEC_32_64,   LFSR_SEQ_RST_ENC} :
                                                                          (WW == 24) && (NKW == 3) ? {LFSR_SEQ_RST_DEC_48_72,   LFSR_SEQ_RST_ENC} :
                                                                          (WW == 24) && (NKW == 4) ? {LFSR_SEQ_RST_DEC_48_96,   LFSR_SEQ_RST_ENC} :
                                                                          (WW == 32) && (NKW == 3) ? {LFSR_SEQ_RST_DEC_64_96,   LFSR_SEQ_RST_ENC} :
                                                                          (WW == 32) && (NKW == 4) ? {LFSR_SEQ_RST_DEC_64_128,  LFSR_SEQ_RST_ENC} :
                                                                          (WW == 48) && (NKW == 2) ? {LFSR_SEQ_RST_DEC_96_96,   LFSR_SEQ_RST_ENC} :
                                                                          (WW == 48) && (NKW == 3) ? {LFSR_SEQ_RST_DEC_96_144,  LFSR_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 2) ? {LFSR_SEQ_RST_DEC_128_128, LFSR_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 3) ? {LFSR_SEQ_RST_DEC_128_192, LFSR_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 4) ? {LFSR_SEQ_RST_DEC_128_256, LFSR_SEQ_RST_ENC} :
                                                                                                     { {LFSR_N{1'b0}}, {LFSR_N{1'b0}}};
localparam logic[1:0]                                   T_SEQ_RSTS      = (WW == 16) && (NKW == 2) ? 'x :
                                                                          (WW == 24) && (NKW == 3) ? 'x :
                                                                          (WW == 24) && (NKW == 4) ? 'x :
                                                                          (WW == 32) && (NKW == 3) ? {T_SEQ_RST_DEC_64_96,   T_SEQ_RST_ENC} :
                                                                          (WW == 32) && (NKW == 4) ? {T_SEQ_RST_DEC_64_128,  T_SEQ_RST_ENC} :
                                                                          (WW == 48) && (NKW == 2) ? {T_SEQ_RST_DEC_96_96,   T_SEQ_RST_ENC} :
                                                                          (WW == 48) && (NKW == 3) ? {T_SEQ_RST_DEC_96_144,  T_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 2) ? {T_SEQ_RST_DEC_128_128, T_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 3) ? {T_SEQ_RST_DEC_128_192, T_SEQ_RST_ENC} :
                                                                          (WW == 64) && (NKW == 4) ? {T_SEQ_RST_DEC_128_256, T_SEQ_RST_ENC} :
                                                                                                      0;

// -- Signals ------------------------------------------------------------------------------------- //
logic               lfsr_outp;
logic[LFSR_C-1:0]   conf_sel;
logic[LFSR_N-1:0]   seq_rst;

// -- LFSR Instance ------------------------------------------------------------------------------- //
assign conf_sel = 1 << mode_i;
assign seq_rst  = LFSR_SEQ_RSTS[mode_i];
lfsr_multi_config
#(
    .N              (LFSR_N),
    .C              (LFSR_C),
    .MATRICES       (LFSR_MATRICES)
)
i_lfsr_u
(
    .clk            (clk),
    .arst_n         (arst_n),
    
    .seq_ld_en_i    (rst_seqs_i),
    .seq_i          (seq_rst),
    
    .conf_sel_i     (conf_sel),
    
    .run_en_i       (run_en_i),
    .outp_o         (lfsr_outp)
);


// -- Output -------------------------------------------------------------------------------------- //
if (Z_SEQ == 0 || Z_SEQ == 1) begin: g_if_z_eq_0_1
    // output sequence will be the LFSR output directly (no further XORing with t)
    assign seq_o = lfsr_outp;
end else begin: g_if_z_gt_1
    // LFSR output is XOR'ed with the period-2 t sequence t = 010101...
    logic t_seq_r;
    always_ff @(posedge clk, negedge arst_n) begin: ff_t_seq
        if (!arst_n) begin
            t_seq_r <= 1'b0;
        end else begin
            if (rst_seqs_i) begin
                t_seq_r <= T_SEQ_RSTS[mode_i];
            end else if (run_en_i) begin
                t_seq_r <= ~t_seq_r;
            end
        end
    end
    
    assign seq_o = lfsr_outp ^ t_seq_r;
end

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

// -- Assertion Properties ------------------------------------------------------------------------ //
// synthesis translate_off
assert property (@(posedge clk) disable iff(!arst_n)
    !(rst_seqs_i & run_en_i)) else $error("Only one operation possible in each cycle, either sequence reset (rst_seqs_i=1) or enc/dec running (run_en_i=1), never both.");
// synthesis translate_on
endmodule
    