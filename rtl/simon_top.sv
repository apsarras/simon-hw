/**
 * @info NSA's Simon cipher top module
 *
 * @author Anastasios Psarras
 *
 * @license MIT license, check license.md
 *
 * @brief Simon generic implementation with a fixed word size n and number of keywords m [ref]
 *        [ref] R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers, "The Simon and Speck Families of Lightweight Block Ciphers", DAC 2015
 *        Depending on the WW and NKW parameters (n and m resp. in [ref]), a different Simon configuration is instantiated.
 *        The following table [ref] summarizes the resulting configuration based on the input params:
 *
 *              -------------------------------------------------------
 *             |  block  |   key   |  word  |   key   |    Config      |
 *             | size 2n | size mn | size n | words m |     Name       |
 *             |-------------------------------------------------------|
 *             |   32    |   64    |   16   |    4    |  Simon 32/64   |
 *             |-------------------------------------------------------|
 *             |   48    |   72    |   24   |    3    |  Simon 48/72   |
 *             |         |   96    |        |    4    |  Simon 48/96   |
 *             |-------------------------------------------------------|
 *             |   64    |   96    |   32   |    3    |  Simon 64/96   |
 *             |         |   128   |        |    4    | Simon 64/128   |
 *             |-------------------------------------------------------|
 *             |   96    |   96    |   48   |    2    |  Simon 96/96   |
 *             |         |   144   |        |    3    | Simon 96/144   |
 *             |-------------------------------------------------------|
 *             |   128   |   128   |   64   |    2    | Simon 128/128  |
 *             |         |   192   |        |    3    | Simon 128/192  |
 *             |         |   256   |        |    4    | Simon 128/256  |
 *              -------------------------------------------------------
 *
 * @param WW        Defines the word size (n in [ref])
 * @param NKW       Defines the number of key words (m in [ref]).
 * @param DATA_RST  Sets whether the plaintext & key registers are resettable to zero (for testability?)
 *                  Note that resettable data FFs will result to a higher area footprint
 */

module simon_top
#(
    parameter int   WW          = 16,
    parameter int   NKW         = 4,
    parameter logic DATA_RST    = 1'b0
)
(
    input  logic                    clk,        // clock, @posedge
    input  logic                    arst_n,     // async reset -- active low
    // Activity
    output logic                    active_o,   // indicates when there's activity in the block (for architectural clock gating perhaps?)
    // Input Interface
    input  logic                    valid_i,    // when asserted, it indicates that input is valid and the block must start processing pt_i/key_i
    output logic                    ready_o,    // when asserted and valid_i is also asserted, the input has been processed
    input  logic                    mode_i,     // 0: encrypt / 1: decrypt (only matters when valid_i is asserted)
    input  logic[2-1:0][WW-1:0]     pt_i,       // input plaintext
    input  logic[NKW-1:0][WW-1:0]   key_i,      // input key
    // Output Interface
    output logic                    valid_o,    // when asserted, a plaintext/ciphertext-key pair has been processed and ct_o contains valid data
    input  logic                    ready_i,    // when asserted and valid_o is also asserted, output ct_o is considered as read
    output logic                    mode_o,     // 0: encrypt / 1: decrypt (only matters when valid_o is asserted)
    output logic[2-1:0][WW-1:0]     ct_o        // output ciphertext (on encryption mode), or plaintext (on decryption mode)
);

// -- Signal Definitions -------------------------------------------------------------------------- //
// FSM to Core signals
logic                   fsm2core_srst;
logic                   fsm2core_mode;
logic                   fsm2core_pt_ld_en;
logic                   fsm2core_pt_run_en;
logic                   fsm2core_key_ld_en;
logic                   fsm2core_key_run_en;
logic[NKW-1:0]          fsm_key_reg_ld_en;
logic                   fsm_key_reg_sel;
logic[WW-1:0]           core_key;
logic[NKW-1:0][WW-1:0]  dec_keys_r;
logic[NKW-1:0][WW-1:0]  core_keys_to_load;

// -- Control FSM --------------------------------------------------------------------------------- //
simon_ctrl_fsm
#(
    .WW                 (WW),
    .NKW                (NKW)
)
i_ctrl_fsm
(
    .clk                (clk),
    .arst_n             (arst_n),
    
    .active_o           (active_o),
    
    .valid_i            (valid_i),
    .ready_o            (ready_o),
    .mode_i             (mode_i),
    
    .core_srst_o        (fsm2core_srst),
    .core_mode_o        (fsm2core_mode),
    .core_pt_ld_en_o    (fsm2core_pt_ld_en),
    .core_pt_run_en_o   (fsm2core_pt_run_en),
    .core_key_ld_en_o   (fsm2core_key_ld_en),
    .core_key_run_en_o  (fsm2core_key_run_en),
    
    .key_reg_ld_en_o    (fsm_key_reg_ld_en),
    .key_reg_sel_o      (fsm_key_reg_sel),
    
    .valid_o            (valid_o),
    .ready_i            (ready_i),
    .mode_o             (mode_o)
);

if (DATA_RST) begin: g_if_data_rst
    always_ff @(posedge clk, negedge arst_n) begin: ff_key_regs
        if (!arst_n) begin
            dec_keys_r <= '0;
        end else begin
            for (int i=0; i<NKW; i++) begin
                if (fsm_key_reg_ld_en[i]) begin
                    dec_keys_r[i] <= core_key;
                end
            end
        end
    end
end else begin: g_if_not_data_rst
    always_ff @(posedge clk, negedge arst_n) begin: ff_key_regs
        for (int i=0; i<NKW; i++) begin
            if (fsm_key_reg_ld_en[i]) begin
                dec_keys_r[i] <= core_key;
            end
        end
    end
end

// -- Simon Core ---------------------------------------------------------------------------------- //
for (genvar i=0; i<NKW; i++) begin
    for (genvar w=0; w<WW; w++) begin
        assign core_keys_to_load[i][w] = (~fsm_key_reg_sel & key_i[i][w]) |
                                         ( fsm_key_reg_sel & dec_keys_r[i][w]);
    end
end

simon_core
#(
    .WW                 (WW),
    .NKW                (NKW),
    .DATA_RST           (DATA_RST)
)
i_core
(
    .clk                (clk),        // active low
    .arst_n             (arst_n),     // async reset -- active low
    
    .srst_i             (fsm2core_srst),     // sync reset -- active high
    .mode_i             (fsm2core_mode),     // 0 for encrypt, 1 for decrypt
    
    .pt_ld_en_i         (fsm2core_pt_ld_en),
    .pt_run_en_i        (fsm2core_pt_run_en),
    .pt_i               (pt_i),       // plaintext parts
    
    .key_ld_en_i        (fsm2core_key_ld_en),
    .key_run_en_i       (fsm2core_key_run_en),
    .key_i              (core_keys_to_load),      // key parts
    
    .ct_o               (ct_o),         // output ciphertext
    .key_o              (core_key)
);


// -- Assertion Properties ------------------------------------------------------------------------ //
// synthesis translate_off
// input interface
assert property (@(posedge clk) disable iff(!arst_n)
    valid_i & ~ready_o |=> $stable({key_i, pt_i, mode_i})) else $error("mode_i, pt_i and key_i should remain stable when valid_i=1 and ready_o=0");
assert property (@(posedge clk) disable iff(!arst_n)
    valid_i & ~ready_o |=> valid_i) else $error("valid_i should remain HIGH while ready_o=0");
// output interface
assert property (@(posedge clk) disable iff(!arst_n)
    valid_o & ~ready_i |=> $stable({ct_o, mode_o})) else $error("mode_o and ct_o should remain stable when valid_o=1 and ready_i=0");
assert property (@(posedge clk) disable iff(!arst_n)
    valid_o & ~ready_i |=> valid_o) else $error("valid_o should remain HIGH while ready_i=0");
// synthesis translate_on

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
