/**
 * @info NSA's Simon cipher core
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
 * @param DATA_RST  Sets whether the plaintext & key registers are resettable to zero (for testing reasons)
 *                  Note that resettable data FFs will result to a higher area footprint
 */

module simon_core
#(
    parameter int   WW          = 16,
    parameter int   NKW         = 4,
    parameter logic DATA_RST    = 1'b0
)
(
    input  logic                    clk,            // clock, @posedge
    input  logic                    arst_n,         // async reset -- active low
    // 
    input  logic                    srst_i,         // reset LFSR & t sequence
    input  logic                    mode_i,         // 0 for encrypt, 1 for decrypt
    
    input  logic                    pt_ld_en_i,     // load plaintext into registers (set pt_i and assert pt_ld_en_i for one cycle)
    input  logic                    pt_run_en_i,    // update plaintext registers (assert for as many cycles as the number of rounds)
    input  logic[2-1:0][WW-1:0]     pt_i,           // plaintext input (2 words)
    
    input  logic                    key_ld_en_i,    // load key into registers (set key_i and assert key_ld_en_i for one cycle)
    input  logic                    key_run_en_i,   // update key registers (assert for as many cycles as the number of rounds)
    input  logic[NKW-1:0][WW-1:0]   key_i,          // key input (NKW words)
    
    output logic[2-1:0][WW-1:0]     ct_o,           // current ciphertext (outputs plaintext regs)
    output logic[WW-1:0]            key_o           // current key (outputs key regs)
);
// -- Constants ----------------------------------------------------------------------------------- //
localparam logic[WW-1:0] C_CONSTANT = (1 << WW) - 4;

// -- Signal Definitions -------------------------------------------------------------------------- //
logic                   seq;
logic[NKW-1:0][WW-1:0]  key_r;
logic[NKW-1:0][WW-1:0]  key_nxt;
logic[1:0][WW-1:0]      pt_r;
logic[1:0][WW-1:0]      pt_nxt;
logic[WW-1:0]           c_xor_z;

// -- Data (plaintext & key) Registers ------------------------------------------------------------ //
if (DATA_RST) begin: if_data_rst
    // Resettable data FFs
    always_ff @(posedge clk, negedge arst_n) begin: ff_key
        if (!arst_n) begin
            key_r <= '{WW{1'b0}};
        end else begin
            if (key_ld_en_i) begin
                key_r <= key_i;
            end else if (key_run_en_i) begin
                key_r <= key_nxt;
            end
        end
    end
    
    always_ff @(posedge clk, negedge arst_n) begin: ff_pt
        if (!arst_n) begin
            pt_r  <= '{WW{1'b0}};
        end else begin
            if (pt_ld_en_i) begin
                pt_r <= pt_i;
            end else if (pt_run_en_i) begin
                pt_r <= pt_nxt;
            end
        end
    end
end else begin: if_no_data_rst
    // Non-resettable data FFs
    always_ff @(posedge clk) begin: ff_key
        if (key_ld_en_i) begin
            key_r <= key_i;
        end else if (key_run_en_i) begin
            key_r <= key_nxt;
        end
    end
    
    always_ff @(posedge clk) begin: ff_pt
        if (pt_ld_en_i) begin
            pt_r <= pt_i;
        end else if (pt_run_en_i) begin
            pt_r <= pt_nxt;
        end
    end
end

// -- Sequence Generator -------------------------------------------------------------------------- //
simon_seq_gen
#(
    .WW         (WW ),
    .NKW        (NKW)
)
i_seq_gen
(
    .clk        (clk),
    .arst_n     (arst_n),
    .rst_seqs_i (srst_i),

    .mode_i     (mode_i),
    
    .run_en_i   (key_run_en_i),
    .seq_o      (seq)
);

assign c_xor_z = C_CONSTANT ^ seq;

// -- Key Schedule -------------------------------------------------------------------------------- //
simon_key_schedule
#(
    .WW         (WW ),
    .NKW        (NKW)
)
i_key_schedule
(
    .mode_i     (mode_i),
    
    .key_cur_i  (key_r),
    .c_xor_z_i  (c_xor_z),
    
    .key_nxt_o  (key_nxt)
);
// -- Round Function ------------------------------------------------------------------------------ //
simon_round
#(
    .WW (WW)
)
i_round
(
    .key_i (key_r[0]),
    
    .x_i   (pt_r[1]),
    .y_i   (pt_r[0]),

    .x_o   (pt_nxt[1]),
    .y_o   (pt_nxt[0])
);

// -- Outputs ------------------------------------------------------------------------------------- //
assign ct_o     = pt_r;
assign key_o    = key_r[0];

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
