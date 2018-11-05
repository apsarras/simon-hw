/**
 * @info n-bit reconfigurable LFSR
 *
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 * @brief Generic n-bit reconfigurable LFSR that generates the pseudo-random sequence of 2**n-1 bits.
 *        The LFSR can have C number of possible configurations. Each C_i configuration is determined
 *        by its MATRIX[C_i] (see @param MATRIX)
 *
 * @param N       defines the size of the generated LFSR (max period 2**N-1)
 * @param C       defines the number of configurations available
 * @param MATRIX  defines the LFSR function, in which all register inputs can be a linear function of 
 *                any combination of current register values. CAUTION ON THE DIMENSIONS! Normal ij indexing!
 *                A matrix M defines the next value n[i] of register r[i], which will be:
 *                     n[i] = (r[0] & M[0][i]) ^ (r[1] & M[1][i]) ^ ... ^ (r[N-1] & M[N-1][i])
 *                e.g. For 3-bit LFSR (N=3) with a matrix of MATRIX = '{3'b111, 3'b001, 3'b101}:
 *                          0 1 2
 *                         ------
 *                     0  | 1 1 1
 *                     1  | 0 0 1
 *                     2  | 1 0 1
 *
 *                n[0] = r[0]^r[2] , n[1] = r[0], n[2] = r[0]^r[1]^r[2]
 */

module lfsr_multi_config
#(
    parameter int                           N        = 3,
    parameter int                           C        = 2,
    parameter logic[C-1:0][0:N-1][0:N-1]    MATRICES = '{{3'b010, 3'b001, 3'b101}, {3'b010, 3'b100, 3'b010}}
)
(
    input  logic                clk,            // clock, @posedge
    input  logic                arst_n,         // async reset -- active low
    // Reset Sequence
    input  logic                seq_ld_en_i,    // when set to 1, regs load the reset sequence (seq_rst_i)
    input  logic[N-1:0]         seq_i,          // reset sequence -- strap to a fixed value (e.g. "11...111")
    // Config 
    input  logic[C-1:0]         conf_sel_i,     // selects config (binary) -- should be changed on reset (sync)
    // LFSR
    input  logic                run_en_i,       // enables LFSR's FF write enables
    output logic                outp_o          // output
);

// -- Helpful Funcs ------------------------------------------------------------------------------- //
// using packed C dimension to avoid compatibility issues
// (i.e. elaboration error with no info @ QuestaSim, Incisiv)
function logic[C-1:0][0:N-1][N-1:0] transpose_n_reverse();
    logic[C-1:0][0:N-1][N-1:0] matret;
    for (int c=0; c<C; c++) begin
        for (int i=0; i<N; i++) begin
            for (int j=0; j<N; j++) begin
                matret[c][i][j] = MATRICES[c][j][i];
            end
        end
    end
    return matret;
endfunction

// -- Self-config --------------------------------------------------------------------------------- //
localparam logic[C-1:0][0:N-1][N-1:0] MATRICES_T = transpose_n_reverse();

// -- Signals ------------------------------------------------------------------------------------- //
logic[N-1:0]        lfsr_r;
logic[N-1:0]        lfsr_nxt;
logic[0:N-1][N-1:0] active_matrix;

// -- Registers ----------------------------------------------------------------------------------- //
always_ff @(posedge clk, negedge arst_n) begin: ff_lfsr
    if (!arst_n) begin
        lfsr_r <= '0;
    end else begin
        if (seq_ld_en_i) begin
            lfsr_r <= seq_i;
        end else if (run_en_i) begin
            lfsr_r <= lfsr_nxt;
        end
    end
end
// -- Comb Logic ---------------------------------------------------------------------------------- //
// Config -- MUX
logic tmp;
always_comb begin: mux_matrix
    for (int i=0; i<N; i++) begin
        for (int j=0; j<N; j++) begin
            tmp = 0;
            for (int c=0; c<C; c++) begin
                tmp = tmp | (conf_sel_i[c] & MATRICES_T[c][i][j]);
            end
            active_matrix[i][j] = tmp;
        end
    end
end
// XORs
for (genvar i=0; i<N; i++) begin: g_for_i
    assign lfsr_nxt[i] = ^(lfsr_r & active_matrix[i]);
end

// -- Output -------------------------------------------------------------------------------------- //
assign outp_o = lfsr_r[N-1];

// -- Assertion Properties ------------------------------------------------------------------------ //
// synthesis translate_off
assert property (@(posedge clk) disable iff(!arst_n)
    run_en_i |-> !seq_ld_en_i) else $error("reset sequence load shall not be enabled (seq_ld_en_i=1) when the LFSR is running (run_en_i=1)");
// synthesis translate_on
endmodule
