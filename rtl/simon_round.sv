/**
 * @info NSA's Simon round algorithm (combinational logic)
 *
 * @author Anastasios Psarras (a.psarras4225@gmail.com)
 *
 * @license MIT license, check license.md
 *
 * @brief Simon generic implementation with a fixed number of keywords m and word size m [ref]
 *        [ref] R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers, "The Simon and Speck Families of Lightweight Block Ciphers", DAC 2015
 *
 * @param WW        Defines the word size (n in [ref])
 */

module simon_round
#(
    parameter int WW    = 16 // WW: Word Width (n) -- Legal values: see 'n' in above table
)
(
    input  logic[WW-1:0] key_i,
    input  logic[WW-1:0] x_i,
    input  logic[WW-1:0] y_i,
    
    output logic[WW-1:0] x_o,
    output logic[WW-1:0] y_o
);

// -- Left Rotation handy function ---------------------------------------------------------------- //
function logic[WW-1:0] rot_left(input logic[WW-1:0] a, input int n);
    return (a << n) | (a >> (WW-n));
endfunction

// -- Outputs -- //
assign y_o = x_i;
assign x_o = y_i ^ (rot_left(x_i, 1) & rot_left(x_i, 8)) ^ rot_left(x_i, 2) ^ key_i;

// synthesis translate_off
initial begin
    #0 assert (WW inside {16, 24, 32, 48, 64}) else $error("Illegal WW parameter value %0d -- legal values: 16, 24, 32, 48, 64", WW);
end
// synthesis translate_on
endmodule