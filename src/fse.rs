pub use crate::types::FseTableKind;

use crate::params::*;
use crate::util::{read_variable_bit_packing, smaller_powers_of_two};
use bitstream_io::{BitRead, BitReader, LittleEndian};
use itertools::Itertools;
use std::{collections::BTreeMap, io::Cursor};

/// A single row in the FSE table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseTableRow {
    /// The FSE state at this row in the FSE table.
    pub state: u64,
    /// The baseline associated with this state.
    pub baseline: u64,
    /// The number of bits to be read from the input bitstream at this state.
    pub num_bits: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u64,
    /// A boolean marker to indicate that as per the state transition rules of FSE codes, this
    /// state was reached for this symbol, however it was already pre-allocated to a prior symbol,
    /// this can happen in case we have symbols with prob=-1.
    pub is_state_skipped: bool,
}

/// Auxiliary data accompanying the FSE table's witness values.
#[derive(Clone, Debug)]
pub struct FseAuxiliaryTableData {
    /// The block index in which this FSE table appears.
    pub block_idx: u64,
    /// Indicates whether the table is pre-defined.
    pub is_predefined: bool,
    /// In RLE mode, record the rle symbol.
    pub rle_symbol: Option<u8>,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
    /// The accuracy log
    pub accuracy_log: u64,
    /// Normalized probability,
    /// Used to indicate actual probability frequency of symbols, with 0 and -1 symbols present
    pub normalised_probs: BTreeMap<u64, i32>,
    /// A map from FseSymbol (weight) to states, also including fields for that state, for
    /// instance, the baseline and the number of bits to read from the FSE bitstream.
    ///
    /// For each symbol, the states as per the state transition rule.
    pub sym_to_states: BTreeMap<u64, Vec<FseTableRow>>,
    // Similar map, but where the states for each symbol are in increasing order (sorted).
    // pub sym_to_sorted_states: BTreeMap<u64, Vec<FseTableRow>>,
}

/// Another form of Fse table that has state as key instead of the FseSymbol.
/// In decoding, symbols are emitted from state-chaining.
/// This representation makes it easy to look up decoded symbol from current state.   
/// Map<state, (symbol, baseline, num_bits)>.
type FseStateMapping = BTreeMap<u64, (u64, u64, u64)>;
type ReconstructedFse = (usize, FseAuxiliaryTableData);

impl FseAuxiliaryTableData {
    pub fn reconstruct_rle(src: &[u8], block_idx: u64) -> std::io::Result<ReconstructedFse> {
        let symbol = src[0] as u64;
        let mut sym_to_states = BTreeMap::new();
        sym_to_states.insert(
            symbol,
            vec![FseTableRow {
                state: 0,
                baseline: 0,
                num_bits: 0,
                symbol,
                is_state_skipped: false,
            }],
        );
        let mut normalised_probs = BTreeMap::new();
        normalised_probs.insert(symbol, 1);

        Ok((
            1,
            Self {
                block_idx,
                is_predefined: false,
                rle_symbol: Some(src[0]),
                table_size: 1,
                accuracy_log: 0,
                normalised_probs,
                sym_to_states,
            },
        ))
    }

    /// While we reconstruct an FSE table from a bitstream, we do not know before reconstruction
    /// how many exact bytes we would finally be reading.
    ///
    /// The number of bytes actually read while reconstruction is called `t` and is returned along
    /// with the reconstructed FSE table. After processing the entire bitstream to reconstruct the
    /// FSE table, if the read bitstream was not byte aligned, then we discard the 1..8 bits from
    /// the last byte that we read from.
    #[allow(non_snake_case)]
    pub fn reconstruct(
        src: &[u8],
        block_idx: u64,
        table_kind: FseTableKind,
        is_predefined: bool,
    ) -> std::io::Result<ReconstructedFse> {
        // construct little-endian bit-reader.
        // let data = src.to_vec();
        let mut reader = BitReader::endian(Cursor::new(src), LittleEndian);

        ////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// Parse Normalised Probabilities ////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let mut normalised_probs = BTreeMap::new();
        let mut offset = 0;

        let (accuracy_log, table_size) = if is_predefined {
            let (predefined_frequencies, accuracy_log) = match table_kind {
                FseTableKind::LLT => (
                    vec![
                        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
                    ],
                    6,
                ),
                FseTableKind::MOT => (
                    vec![
                        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
                        -1, -1, -1, -1,
                    ],
                    5,
                ),
                FseTableKind::MLT => (
                    vec![
                        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
                        -1, -1, -1, -1,
                    ],
                    6,
                ),
            };
            for (symbol, freq) in predefined_frequencies.into_iter().enumerate() {
                normalised_probs.insert(symbol as u64, freq);
            }
            (accuracy_log, 1 << accuracy_log)
        } else {
            offset += 4;
            let accuracy_log = reader.read::<u8>(offset)? + 5;
            let table_size = 1 << accuracy_log;
            let mut R = table_size;
            let mut symbol = 0;
            while R > 0 {
                // TODO: invalid data (like 0xFF 0xFF 0xFF) would cause an infinity
                // loop, can we detect that and throw error?

                // number of bits and value read from the variable bit-packed data.
                // And update the total number of bits read so far.
                let (n_bits_read, _value_read, value_decoded) =
                    read_variable_bit_packing(src, offset, R + 1)?;
                reader.skip(n_bits_read)?;
                offset += n_bits_read;

                // Number of states allocated to this symbol.
                // - prob=-1 => 1
                // - prob=0  => 0
                // - prob>=1 => prob
                let N = match value_decoded {
                    0 => 1,
                    _ => value_decoded - 1,
                };

                // When a symbol has a value==0, it signifies a case of prob=-1 (or probability
                // "less than 1"), where such symbols are allocated states from the
                // end and retreating. In such cases, we reset the FSE state, i.e.
                // read accuracy_log number of bits from the bitstream with a
                // baseline==0x00.
                if value_decoded == 0 {
                    normalised_probs.insert(symbol, -1);
                    symbol += 1;
                }

                // When a symbol has a value==1 (prob==0), it is followed by a 2-bits repeat flag.
                // This repeat flag tells how many probabilities of zeroes follow
                // the current one. It provides a number ranging from 0 to 3. If it
                // is a 3, another 2-bits repeat flag follows, and so on.
                if value_decoded == 1 {
                    normalised_probs.insert(symbol, 0);
                    symbol += 1;
                    loop {
                        let repeat_bits = reader.read::<u8>(2)?;
                        offset += 2;

                        for k in 0..repeat_bits {
                            normalised_probs.insert(symbol + (k as u64), 0);
                        }
                        symbol += repeat_bits as u64;

                        if repeat_bits < 3 {
                            break;
                        }
                    }
                }

                // When a symbol has a value>1 (prob>=1), it is allocated that many number of states
                // in the FSE table.
                if value_decoded > 1 {
                    normalised_probs.insert(symbol, N as i32);
                    symbol += 1;
                }

                // remove N slots from a total of R.
                R -= N;
            }
            (accuracy_log, table_size)
        };

        // ignore any bits left to be read until byte-aligned.
        let t = if is_predefined {
            0
        } else {
            (((offset as usize) - 1) / N_BITS_PER_BYTE) + 1
        };

        // read the trailing section
        if t * N_BITS_PER_BYTE > (offset as usize) {
            let bits_remaining = t * N_BITS_PER_BYTE - offset as usize;
            let _trailing_value = reader.read::<u8>(bits_remaining as u32)? as u64;
        }

        // sanity check: sum(probabilities) == table_size.
        assert_eq!(
            normalised_probs
                .values()
                .map(|&prob| if prob == -1 { 1u64 } else { prob as u64 })
                .sum::<u64>(),
            table_size
        );

        ////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////// Allocate States to Symbols ///////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let sym_to_states = Self::transform_normalised_probs(&normalised_probs, accuracy_log);

        Ok((
            t,
            Self {
                block_idx,
                is_predefined,
                rle_symbol: None,
                table_size,
                accuracy_log: accuracy_log as u64,
                normalised_probs,
                sym_to_states,
                //sym_to_sorted_states,
            },
        ))
    }

    #[allow(non_snake_case)]
    fn transform_normalised_probs(
        normalised_probs: &BTreeMap<u64, i32>,
        accuracy_log: u8,
    ) -> BTreeMap<u64, Vec<FseTableRow>> {
        // TODO: still need optimizations
        let table_size = 1 << accuracy_log;

        let mut sym_to_states = BTreeMap::new();
        let mut state = 0;
        let mut retreating_state = table_size - 1;
        let mut allocated_states = BTreeMap::<u64, bool>::new();

        // We start with the symbols that have prob=-1.
        for (&symbol, _prob) in normalised_probs
            .iter()
            .filter(|(_symbol, &prob)| prob == -1)
        {
            allocated_states.insert(retreating_state, true);
            let fse_table_row = FseTableRow {
                state: retreating_state,
                num_bits: accuracy_log as u64,
                baseline: 0,
                symbol,
                is_state_skipped: false,
            };
            sym_to_states.insert(symbol, vec![fse_table_row.clone()]);
            retreating_state -= 1;
        }

        // We now move to the symbols with prob>=1.
        for (&symbol, &prob) in normalised_probs
            .iter()
            .filter(|(_symbol, &prob)| prob.is_positive())
        {
            let N = prob as usize;
            let mut count = 0;
            let mut states_with_skipped: Vec<(u64, bool)> = Vec::with_capacity(N);
            while count < N {
                if allocated_states.contains_key(&state) {
                    // if state has been pre-allocated to some symbol with prob=-1.
                    states_with_skipped.push((state, true));
                } else {
                    // if state is not yet allocated, i.e. available for this symbol.
                    states_with_skipped.push((state, false));
                    count += 1;
                }

                // update state.
                state += (table_size >> 1) + (table_size >> 3) + 3;
                state &= table_size - 1;
            }
            let sorted_states = states_with_skipped
                .iter()
                .filter(|&(_s, is_state_skipped)| !is_state_skipped)
                .map(|&(s, _)| s)
                .sorted()
                .collect::<Vec<u64>>();
            let (smallest_spot_idx, nbs) = smaller_powers_of_two(table_size, N as u64);
            let baselines = if N == 1 {
                vec![0x00]
            } else {
                let mut rotated_nbs = nbs.clone();
                rotated_nbs.rotate_left(smallest_spot_idx);

                let mut baselines = std::iter::once(0x00)
                    .chain(rotated_nbs.iter().scan(0x00, |baseline, nb| {
                        *baseline += 1 << nb;
                        Some(*baseline)
                    }))
                    .take(N)
                    .collect::<Vec<u64>>();

                baselines.rotate_right(smallest_spot_idx);
                baselines
            };
            sym_to_states.insert(
                symbol,
                states_with_skipped
                    .iter()
                    .map(|&(s, is_state_skipped)| {
                        let (baseline, nb) = match sorted_states.iter().position(|&ss| ss == s) {
                            None => (0, 0),
                            Some(sorted_idx) => (baselines[sorted_idx], nbs[sorted_idx]),
                        };
                        FseTableRow {
                            state: s,
                            num_bits: nb,
                            baseline,
                            symbol,
                            is_state_skipped,
                        }
                    })
                    .collect(),
            );
        }

        sym_to_states
    }

    /// Convert an FseAuxiliaryTableData into a state-mapped representation.
    /// This makes it easier to lookup state-chaining during decoding.
    pub fn parse_state_table(&self) -> FseStateMapping {
        let rows: Vec<FseTableRow> = self
            .sym_to_states
            .values()
            .flat_map(|v| v.clone())
            .collect();
        let mut state_table: FseStateMapping = BTreeMap::new();

        for row in rows {
            if !row.is_state_skipped {
                state_table.insert(row.state, (row.symbol, row.baseline, row.num_bits));
            }
        }

        state_table
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    //use crate::fse::Fse;

    #[test]
    fn test_fse_reconstruction() -> std::io::Result<()> {
        // Only the first 4 bytes are meaningful and the FSE
        // reconstruction should read bitstreams only until the end of the 4th byte. The 3
        // other bytes are garbage (for the purpose of this test case), and we want to make
        // sure FSE reconstruction ignores them.
        let src = vec![0x30, 0x6f, 0x9b, 0x03, 0xff, 0xff, 0xff];

        let (n_bytes, table) =
            FseAuxiliaryTableData::reconstruct(&src, 1, FseTableKind::LLT, false)?;

        // TODO: assert equality for the entire table.
        // for now only comparing state/baseline/nb for S1, i.e. weight == 1.
        let sorted_states = table
            .sym_to_states
            .get(&1)
            .unwrap()
            .iter()
            .filter(|st| !st.is_state_skipped)
            .sorted_by_key(|s| s.state)
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(n_bytes, 4);
        assert_eq!(
            sorted_states,
            [
                (0x03, 0x10, 3),
                (0x0c, 0x18, 3),
                (0x11, 0x00, 2),
                (0x15, 0x04, 2),
                (0x1a, 0x08, 2),
                (0x1e, 0x0c, 2),
            ]
            .iter()
            .map(|&(state, baseline, num_bits)| FseTableRow {
                state,
                symbol: 1,
                baseline,
                num_bits,
                is_state_skipped: false,
            })
            .collect::<Vec<FseTableRow>>(),
        );

        Ok(())
    }

    // #[test]
    // fn test_fse_reconstruction_predefined_tables() {
    //     // Here we test whether we can actually reconstruct the FSE table for distributions that
    //     // include prob=-1 cases, one such example is the Predefined FSE table as per
    //     // specifications.
    //     let default_distribution_llt = vec![
    //         4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1,
    //         1, 1, 1, -1, -1, -1, -1,
    //     ];
    //     let default_distribution_mlt = vec![
    //         1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    //         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    //     ];
    //     let default_distribution_mot = vec![
    //         1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1,
    //         -1,
    //     ];

    //     for (table_kind, default_distribution) in [
    //         (FseTableKind::LLT, default_distribution_llt),
    //         (FseTableKind::MLT, default_distribution_mlt),
    //         (FseTableKind::MOT, default_distribution_mot),
    //     ] {
    //         let normalised_probs = {
    //             let mut normalised_probs = BTreeMap::new();
    //             for (i, &prob) in default_distribution.iter().enumerate() {
    //                 normalised_probs.insert(i as u64, prob);
    //             }
    //             normalised_probs
    //         };
    //         let (sym_to_states, _sym_to_sorted_states) =
    //             FseAuxiliaryTableData::transform_normalised_probs(
    //                 &normalised_probs,
    //                 table_kind.accuracy_log(),
    //             );
    //         let expected_predefined_table = predefined_fse(table_kind);

    //         let mut computed_predefined_table = sym_to_states
    //             .values()
    //             .flatten()
    //             .filter(|row| !row.is_state_skipped)
    //             .collect::<Vec<_>>();
    //         computed_predefined_table.sort_by_key(|row| row.state);

    //         for (i, (expected, computed)) in expected_predefined_table
    //             .iter()
    //             .zip_eq(computed_predefined_table.iter())
    //             .enumerate()
    //         {
    //             assert_eq!(computed.state, expected.state, "state mismatch at i={}", i);
    //             assert_eq!(
    //                 computed.symbol, expected.symbol,
    //                 "symbol mismatch at i={}",
    //                 i
    //             );
    //             assert_eq!(
    //                 computed.baseline, expected.baseline,
    //                 "baseline mismatch at i={}",
    //                 i
    //             );
    //             assert_eq!(computed.num_bits, expected.nb, "nb mismatch at i={}", i);
    //         }
    //     }
    // }

    #[test]
    fn test_sequences_fse_reconstruction() -> std::io::Result<()> {
        let src = vec![
            0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e,
        ];

        let (_n_bytes, table) =
            FseAuxiliaryTableData::reconstruct(&src, 0, FseTableKind::LLT, false)?;
        let parsed_state_map = table.parse_state_table();

        let mut expected_state_table = BTreeMap::new();

        let expected_state_table_states: [[u64; 4]; 64] = [
            [0, 0, 4, 2],
            [1, 0, 8, 2],
            [2, 0, 12, 2],
            [3, 0, 16, 2],
            [4, 0, 20, 2],
            [5, 0, 24, 2],
            [6, 1, 32, 4],
            [7, 1, 48, 4],
            [8, 2, 0, 5],
            [9, 3, 0, 4],
            [10, 4, 16, 4],
            [11, 4, 32, 4],
            [12, 6, 0, 5],
            [13, 8, 32, 5],
            [14, 9, 32, 5],
            [15, 10, 32, 5],
            [16, 12, 0, 6],
            [17, 14, 0, 6],
            [18, 15, 0, 4],
            [19, 17, 0, 6],
            [20, 20, 0, 6],
            [21, 24, 32, 5],
            [22, 0, 28, 2],
            [23, 0, 32, 2],
            [24, 0, 36, 2],
            [25, 0, 40, 2],
            [26, 0, 44, 2],
            [27, 1, 0, 3],
            [28, 1, 8, 3],
            [29, 2, 32, 5],
            [30, 3, 16, 4],
            [31, 4, 48, 4],
            [32, 4, 0, 3],
            [33, 5, 0, 5],
            [34, 7, 0, 6],
            [35, 8, 0, 4],
            [36, 9, 0, 4],
            [37, 10, 0, 4],
            [38, 13, 0, 5],
            [39, 15, 16, 4],
            [40, 16, 0, 6],
            [41, 18, 0, 5],
            [42, 24, 0, 4],
            [43, 0, 48, 2],
            [44, 0, 52, 2],
            [45, 0, 56, 2],
            [46, 0, 60, 2],
            [47, 0, 0, 1],
            [48, 0, 2, 1],
            [49, 1, 16, 3],
            [50, 1, 24, 3],
            [51, 3, 32, 4],
            [52, 3, 48, 4],
            [53, 4, 8, 3],
            [54, 5, 32, 5],
            [55, 6, 32, 5],
            [56, 8, 16, 4],
            [57, 9, 16, 4],
            [58, 10, 16, 4],
            [59, 13, 32, 5],
            [60, 15, 32, 4],
            [61, 15, 48, 4],
            [62, 18, 32, 5],
            [63, 24, 16, 4],
        ];

        for state in expected_state_table_states {
            expected_state_table.insert(state[0], (state[1], state[2], state[3]));
        }

        assert!(parsed_state_map == expected_state_table);

        Ok(())
    }
}
