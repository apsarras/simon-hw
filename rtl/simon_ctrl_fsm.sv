/**
 * @info NSA's Simon cipher control FSM (produces simon_core's control signals)
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

module simon_ctrl_fsm
#(
    parameter int   WW          = 16,
    parameter int   NKW         = 4
)
(
    input  logic                    clk,                // clock, @posedge
    input  logic                    arst_n,             // async reset -- active low
    output logic                    active_o,           // asserted when not idle (used for architectural clock gating)
    // Input Interface
    input  logic                    valid_i,            // when asserted, the FSM will start its work
    output logic                    ready_o,            // when asserted, and valid_i is asserted, the current input has been completely processed
    input  logic                    mode_i,             // when valid_i is asserted, it defines the desired functionality: 0 for encrypton, 1 for decryption
    // Control to core
    output logic                    core_srst_o,        // to simon_core: resets LFSR & sequences
    output logic                    core_mode_o,        // to simon_core: enc/dec mode
    output logic                    core_pt_ld_en_o,    // to simon_core: load plaintext regs with input pt_i
    output logic                    core_pt_run_en_o,   // to simon_core: update plaintext regs
    output logic                    core_key_ld_en_o,   // to simon_core: load key regs with input key_i
    output logic                    core_key_run_en_o,  // to simon_core: update key regs
    // Key Temp Registers
    output logic[NKW-1:0]           key_reg_ld_en_o,    // one-hot signal, if bit i is asserted, load key reg i
    output logic                    key_reg_sel_o,      // selects which keys will load the core's key regs: 0 for input (key_i), 1 for stored keys (see simon_top)
    // Output Interface
    output logic                    valid_o,            // when asserted, a plaintext/ciphertext-key pair has been processed
    input  logic                    ready_i,            // when asserted and valid_o is asserted, the output has successfully been transfered to the environment
    output logic                    mode_o              // when valid_o is asserted, it indicates whether the output is the result of an encryption (0) or decryption
);
// -- Constants ----------------------------------------------------------------------------------- //
// mode global constant values (0: encryption, 1: decryption)
import simon_const_pkg::MODE_ENC;
import simon_const_pkg::MODE_DEC;
// number of rounds, depending on the configuration
localparam int N_ROUNDS = (WW == 16) && (NKW == 2) ? 32 :
                          (WW == 24) && (NKW == 3) ? 36 :
                          (WW == 24) && (NKW == 4) ? 36 :
                          (WW == 32) && (NKW == 3) ? 42 :
                          (WW == 32) && (NKW == 4) ? 44 :
                          (WW == 48) && (NKW == 2) ? 52 :
                          (WW == 48) && (NKW == 3) ? 54 :
                          (WW == 64) && (NKW == 2) ? 68 :
                          (WW == 64) && (NKW == 3) ? 69 :
                          (WW == 64) && (NKW == 4) ? 72 :
                                                     0;
// FSM states
typedef enum {S_IDLE,
              S_ENC_PRE, S_ENC_RUN, 
              S_DEC_PRE_KEY, S_DEC_KEY_RUN, S_DEC_PRE, S_DEC_RUN,
              S_OUTPUT} fsm_state_t;
fsm_state_t state_cur;
fsm_state_t state_nxt;
// round counter signals
logic[$clog2(N_ROUNDS)-1:0] round_cnt_r;
logic                       round_cnt_rst;
logic                       round_cnt_incr;

// -- Round Counter ------------------------------------------------------------------------------- //
// reset counter when loading in progress
assign round_cnt_rst    = core_pt_ld_en_o | core_key_ld_en_o;
// increase counter while the algo is running
assign round_cnt_incr   = core_pt_run_en_o | core_key_run_en_o;
always_ff @(posedge clk, negedge arst_n) begin: ff_round_cnt
    if (!arst_n) begin
        round_cnt_r <= '0;
    end else begin
        if (round_cnt_rst) begin
            round_cnt_r <= '0;
        end else if (round_cnt_incr) begin
            round_cnt_r <= round_cnt_r + 1;
        end
    end
end

// -- FSM ----------------------------------------------------------------------------------------- //
always_ff @(posedge clk, negedge arst_n) begin: ff_fsm
    if (!arst_n) begin
        state_cur <= S_IDLE;
    end else begin
        state_cur <= state_nxt;
    end
end

always_comb begin: comb_fsm_nxt
    state_nxt = state_cur;
    
    case (state_cur)
        // Idle -- does nothing, only waits for input valid
        // when input valid is asserted, will move to Encryption or Decryption cycle depending on mode_i
        S_IDLE: begin
            if (valid_i && (mode_i == MODE_ENC)) begin
                state_nxt = S_ENC_PRE;
            end else if (valid_i && (mode_i == MODE_DEC)) begin
                state_nxt = S_DEC_PRE_KEY;
            end
        end
        
        // Pre-Encryption -- resets sequences and loads key & plaintext
        S_ENC_PRE: begin
            state_nxt = S_ENC_RUN;
        end
        
        // Encryption -- runs for T rounds until final ciphertext is generated
        S_ENC_RUN: begin
            if (round_cnt_r == (N_ROUNDS-1)) begin
                state_nxt = S_OUTPUT;
            end
        end
        
        // Pre-Decryption Key Prepare -- resets sequences and loads key
        S_DEC_PRE_KEY: begin
            state_nxt = S_DEC_KEY_RUN;
        end
        
        // Decryption Key Prepare -- runs for T rounds until the last Keys are generated
        S_DEC_KEY_RUN: begin
            if (round_cnt_r == (N_ROUNDS-1)) begin
                state_nxt = S_DEC_PRE;
            end
        end
        
        // Pre-decryption --  resets sequences and loads key & plaintext
        S_DEC_PRE: begin
            state_nxt = S_DEC_RUN;
        end
        
        // Decryption -- runs for T rounds until final plaintext is generated
        S_DEC_RUN: begin
            if (round_cnt_r == (N_ROUNDS-1)) begin
                state_nxt = S_OUTPUT;
            end
        end
        
        // Output -- asserts valid and sets ouputs
        S_OUTPUT: begin
            if (ready_i) begin
                state_nxt = S_IDLE;
            end
        end
    endcase
end

// -- Signals to the core ------------------------------------------------------------------------- //
assign core_srst_o          = (state_cur == S_ENC_PRE) | (state_cur == S_DEC_PRE_KEY) | (state_cur == S_DEC_PRE);
assign core_mode_o          = (state_cur == S_DEC_RUN) || (state_cur == S_DEC_PRE) ? MODE_DEC : MODE_ENC;
assign core_pt_ld_en_o      = (state_cur == S_ENC_PRE) | (state_cur == S_DEC_PRE);
assign core_pt_run_en_o     = (state_cur == S_ENC_RUN) | (state_cur == S_DEC_RUN);
assign core_key_ld_en_o     = (state_cur == S_ENC_PRE) | (state_cur == S_DEC_PRE_KEY) | (state_cur == S_DEC_PRE);
assign core_key_run_en_o    = (state_cur == S_ENC_RUN) | (state_cur == S_DEC_KEY_RUN) | (state_cur == S_DEC_RUN);
assign key_reg_sel_o        = (state_cur == S_DEC_PRE);

if (NKW == 4) begin: g_if_nkw_eq_4
    assign key_reg_ld_en_o = (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-3)) ? (1 << 3) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-2)) ? (1 << 2) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-1)) ? (1 << 1) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1  )) ? (1     ) :
                                                                                               '0;
end else if (NKW == 3) begin:g_if_nkw_eq_3
    assign key_reg_ld_en_o = (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-2)) ? (1 << 2) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-1)) ? (1 << 1) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1  )) ? (1     ) :
                                                                                               '0;
end else if (NKW == 2) begin:g_if_nkw_eq_2
    assign key_reg_ld_en_o = (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1-1)) ? (1 << 1) :
                             (state_cur == S_DEC_KEY_RUN) && (round_cnt_r == (N_ROUNDS-1  )) ? (1     ) :
                                                                                               '0;
end

// -- Output -------------------------------------------------------------------------------------- //
always_ff @(posedge clk, negedge arst_n) begin: ff_ready_o
    if (!arst_n) begin
        ready_o <= 0;
    end else begin
        if ( (state_cur == S_ENC_PRE) || (state_cur == S_DEC_PRE) ) begin
            ready_o <= 1;
        end else begin
            ready_o <= 0;
        end
    end
end

always_ff @(posedge clk, negedge arst_n) begin: ff_mode_o
    if (!arst_n) begin
        mode_o <= 0;
    end else begin
        if (state_nxt == S_OUTPUT) begin
            if (state_cur == S_ENC_RUN) begin
                mode_o <= MODE_ENC;
            end else begin // S_DEC_RUN
                mode_o <= MODE_DEC;
            end
        end
    end
end

assign valid_o = (state_cur == S_OUTPUT) ? 1'b1 : 1'b0;
assign active_o = (state_cur == S_IDLE) ? 1'b0 : 1'b1;

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
// `default_nettype wire
