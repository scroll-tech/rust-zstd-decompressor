use crate::params::*;
use crate::types::*;
use crate::util::{be_bits_to_value, increment_idx, le_bits_to_value, value_bits_le};

use anyhow::Result;

const CMOT_N: u64 = 31;

/// FrameHeaderDescriptor and FrameContentSize
fn process_frame_header(
    src: &[u8],
    last_state: ZstdDecodingState,
) -> Result<(usize, ZstdDecodingState)> {
    let byte_offset = last_state.encoded_data.byte_idx;
    let src = &src[byte_offset as usize..];

    let fhd_byte = src
        .first()
        .expect("FrameHeaderDescriptor byte should exist");
    let value_bits = value_bits_le(*fhd_byte);

    assert_eq!(value_bits[0], 0, "dictionary ID should not exist");
    assert_eq!(value_bits[1], 0, "dictionary ID should not exist");
    assert_eq!(value_bits[2], 0, "content checksum should not exist");
    assert_eq!(value_bits[3], 0, "reserved bit should not be set");
    assert_eq!(value_bits[4], 0, "unused bit should not be set");
    assert_eq!(value_bits[5], 1, "single segment expected");

    // the number of bytes taken to represent FrameContentSize.
    let fcs_tag_len: usize = match value_bits[7] * 2 + value_bits[6] {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!("2-bit value"),
    };

    let src = &src[1..];
    let fcs = {
        let fcs = src
            .iter()
            .take(fcs_tag_len)
            .rev()
            .fold(0u64, |acc, &byte| acc * 256u64 + (byte as u64));
        match fcs_tag_len {
            2 => fcs + 256,
            _ => fcs,
        }
    };

    Ok((
        fcs as usize,
        ZstdDecodingState {
            state: ZstdState {
                tag: ZstdTag::FrameContentSize,
                tag_next: ZstdTag::BlockHeader,
                block_idx: 0,
                max_tag_len: ZstdTag::FrameContentSize.max_len(),
                tag_len: fcs_tag_len as u64,
            },
            encoded_data: EncodedDataCursor {
                byte_idx: byte_offset + 1 + fcs_tag_len as u64,
                encoded_len: last_state.encoded_data.encoded_len,
            },
            decoded_data: last_state.decoded_data,
            bitstream_read_data: None,
            fse_data: None,
            literal_data: Vec::new(),
            repeated_offset: last_state.repeated_offset,
        },
    ))
}

fn process_block(
    src: &[u8],
    block_idx: u64,
    last_state: ZstdDecodingState,
) -> Result<(ZstdDecodingState, BlockInfo)> {
    let (mut last_state, block_info) = process_block_header(src, block_idx, last_state)?;

    let byte_offset = last_state.encoded_data.byte_idx as usize;
    //println!("offset after block header {} of block {}, block len {}", byte_offset, block_idx, block_info.block_len);

    let last_state = match block_info.block_type {
        BlockType::ZstdCompressedBlock => process_block_zstd(
            src,
            block_idx,
            last_state,
            block_info.block_len,
            block_info.is_last_block,
        ),
        BlockType::RawBlock => {
            last_state.state.tag = ZstdTag::BlockContent;
            last_state.state.tag_next = ZstdTag::BlockHeader;
            last_state.state.tag_len = block_info.block_len as u64;
            last_state.encoded_data.byte_idx += block_info.block_len as u64;

            let src = &src[byte_offset..];
            assert!(src.len() >= block_info.block_len);
            last_state
                .decoded_data
                .extend_from_slice(&src[..block_info.block_len]);
            Ok(last_state)
        }
        BlockType::RleBlock => {
            last_state.state.tag = ZstdTag::BlockContent;
            last_state.state.tag_next = ZstdTag::BlockHeader;
            last_state.state.tag_len = 1;
            last_state.encoded_data.byte_idx += 1;

            let src = &src[byte_offset..];
            assert!(!src.is_empty());
            let new_size = last_state.decoded_data.len() + block_info.block_len;
            last_state.decoded_data.resize(new_size, src[0]);
            Ok(last_state)
        }
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    }?;

    Ok((last_state, block_info))
}

fn process_block_header(
    src: &[u8],
    block_idx: u64,
    last_state: ZstdDecodingState,
) -> Result<(ZstdDecodingState, BlockInfo)> {
    let byte_offset = last_state.encoded_data.byte_idx;
    let src = &src[byte_offset as usize..];

    let mut block_info = BlockInfo {
        block_idx: block_idx as usize,
        ..Default::default()
    };
    assert!(src.len() >= N_BLOCK_HEADER_BYTES);
    let bh_bytes = &src[..N_BLOCK_HEADER_BYTES];

    block_info.is_last_block = (bh_bytes[0] & 1) == 1;
    block_info.block_type = BlockType::from((bh_bytes[0] >> 1) & 3);
    block_info.block_len =
        (bh_bytes[2] as usize * 256 * 256 + bh_bytes[1] as usize * 256 + bh_bytes[0] as usize) >> 3;

    let tag_next = match block_info.block_type {
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockLiteralsHeader,
        // TODO: we can support raw block / rle blow now
        BlockType::RawBlock | BlockType::RleBlock => ZstdTag::BlockContent,
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    };

    Ok((
        ZstdDecodingState {
            state: ZstdState {
                tag: ZstdTag::BlockHeader,
                tag_next,
                block_idx,
                max_tag_len: ZstdTag::BlockHeader.max_len(),
                tag_len: N_BLOCK_HEADER_BYTES as u64,
            },
            encoded_data: EncodedDataCursor {
                byte_idx: byte_offset + N_BLOCK_HEADER_BYTES as u64,
                encoded_len: last_state.encoded_data.encoded_len,
            },
            literal_data: Vec::new(),
            bitstream_read_data: None,
            decoded_data: last_state.decoded_data,
            fse_data: None,
            repeated_offset: last_state.repeated_offset,
        },
        block_info,
    ))
}

#[allow(clippy::too_many_arguments)]
fn process_block_zstd(
    src: &[u8],
    block_idx: u64,
    last_state: ZstdDecodingState,
    block_size: usize,
    last_block: bool,
) -> Result<ZstdDecodingState> {
    let byte_offset = last_state.encoded_data.byte_idx as usize;
    let expected_end_offset = byte_offset + block_size;

    // 1-5 bytes LiteralSectionHeader
    let (last_state, regen_size) = process_block_zstd_literals_header(src, block_idx, last_state)?;
    //println!("offset after literal header {} of block {}, literal size {}", last_state.encoded_data.byte_idx, block_idx, regen_size);

    // Literal body
    let byte_offset = last_state.encoded_data.byte_idx as usize;
    let literal_bytes = &src[byte_offset..];

    // TODO: optimize this vector
    let literal_data = literal_bytes[..regen_size]
        .iter()
        .map(|b| *b as u64)
        .collect();

    let last_state = ZstdDecodingState {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockLiteralsRawBytes,
            tag_next: ZstdTag::ZstdBlockSequenceHeader,
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockLiteralsRawBytes.max_len(),
            tag_len: regen_size as u64,
        },
        encoded_data: EncodedDataCursor {
            byte_idx: (byte_offset + regen_size) as u64,
            encoded_len: last_state.encoded_data.encoded_len,
        },
        literal_data,
        decoded_data: last_state.decoded_data,
        fse_data: None,
        repeated_offset: last_state.repeated_offset,
        bitstream_read_data: None,
    };

    let last_state =
        process_sequences(src, block_idx, expected_end_offset, last_state, last_block)?;

    // sanity check:
    assert_eq!(
        last_state.encoded_data.byte_idx as usize, expected_end_offset,
        "end offset after tag=SequencesData mismatch"
    );

    Ok(last_state)
}

#[allow(clippy::too_many_arguments)]
fn process_sequences(
    src: &[u8],
    block_idx: u64,
    expected_seq_size: usize,
    last_state: ZstdDecodingState,
    last_block: bool,
) -> Result<ZstdDecodingState> {
    let _encoded_len = last_state.encoded_data.encoded_len;
    let byte_offset = last_state.encoded_data.byte_idx;
    let src = &src[byte_offset as usize..expected_seq_size];

    //////////////////////////////////////////////////////
    ///// Sequence Section Part 1: Sequence Header  //////
    //////////////////////////////////////////////////////

    assert!(!src.is_empty(), "First byte of sequence header must exist.");
    let byte0 = src[0];
    assert!(byte0 > 0u8, "Sequences can't be of 0 length");

    let (_num_of_sequences, num_sequence_header_bytes) = if byte0 < 128 {
        (byte0 as u64, 2usize)
    } else {
        assert!(src.len() >= 2, "Next byte of sequence header must exist.");
        let byte1 = src[1];
        if byte0 < 255 {
            ((((byte0 - 128) as u64) << 8) + byte1 as u64, 3)
        } else {
            assert!(src.len() >= 3, "Third byte of sequence header must exist.");
            let byte2 = src[2];
            ((byte1 as u64) + ((byte2 as u64) << 8) + 0x7F00, 4)
        }
    };

    assert!(
        src.len() >= num_sequence_header_bytes,
        "Compression mode byte must exist."
    );
    let compression_mode_byte = src[num_sequence_header_bytes - 1];
    let mode_bits = value_bits_le(compression_mode_byte);

    let literal_lengths_mode = mode_bits[6] + mode_bits[7] * 2;
    let offsets_mode = mode_bits[4] + mode_bits[5] * 2;
    let match_lengths_mode = mode_bits[2] + mode_bits[3] * 2;
    let reserved = mode_bits[0] + mode_bits[1] * 2;

    assert!(reserved == 0, "Reserved bits must be 0");

    // Note: Only 2 modes of FSE encoding are accepted (instead of 4):
    // 0 - Predefined.
    // 2 - Variable bit packing.
    assert!(
        literal_lengths_mode == 2 || literal_lengths_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    assert!(
        offsets_mode == 2 || offsets_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    assert!(
        match_lengths_mode == 2 || match_lengths_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    let _compression_mode = [
        literal_lengths_mode > 0,
        offsets_mode > 0,
        match_lengths_mode > 0,
    ];

    let is_all_predefined_fse = literal_lengths_mode + offsets_mode + match_lengths_mode < 1;

    let last_state = ZstdDecodingState {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceHeader,
            tag_next: if is_all_predefined_fse {
                ZstdTag::ZstdBlockSequenceData
            } else {
                ZstdTag::ZstdBlockSequenceFseCode
            },
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockSequenceHeader.max_len(),
            tag_len: num_sequence_header_bytes as u64,
        },
        encoded_data: EncodedDataCursor {
            byte_idx: byte_offset + num_sequence_header_bytes as u64,
            encoded_len: last_state.encoded_data.encoded_len,
        },
        bitstream_read_data: None,
        decoded_data: last_state.decoded_data,
        fse_data: None,
        literal_data: last_state.literal_data,
        repeated_offset: last_state.repeated_offset,
    };

    /////////////////////////////////////////////////
    ///// Sequence Section Part 2: FSE Tables  //////
    /////////////////////////////////////////////////
    // let byte_offset = sequence_header_end_offset;
    // let fse_starting_byte_offset = byte_offset;
    let byte_offset = last_state.encoded_data.byte_idx;
    //println!("offset after seq header {} of block {}", byte_offset, block_idx);
    let src = &src[num_sequence_header_bytes..];

    // Literal Length Table (LLT)
    let (n_fse_bytes_llt, table_llt) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::LLT,
        literal_lengths_mode < 2,
    )
    .expect("Reconstructing FSE-packed Literl Length (LL) table should not fail.");
    let llt = table_llt.parse_state_table();
    // Determine the accuracy log of LLT
    let al_llt = if literal_lengths_mode > 0 {
        table_llt.accuracy_log
    } else {
        6
    };

    // Cooked Match Offset Table (CMOT)
    let src = &src[n_fse_bytes_llt..];
    let (n_fse_bytes_cmot, table_cmot) =
        FseAuxiliaryTableData::reconstruct(src, block_idx, FseTableKind::MOT, offsets_mode < 2)
            .expect("Reconstructing FSE-packed Cooked Match Offset (CMO) table should not fail.");
    let cmot = table_cmot.parse_state_table();
    // Determine the accuracy log of CMOT
    let al_cmot = if offsets_mode > 0 {
        table_cmot.accuracy_log
    } else {
        5
    };

    // Match Length Table (MLT)
    let src = &src[n_fse_bytes_cmot..];
    let (n_fse_bytes_mlt, table_mlt) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::MLT,
        match_lengths_mode < 2,
    )
    .expect("Reconstructing FSE-packed Match Length (ML) table should not fail.");
    let mlt = table_mlt.parse_state_table();
    // Determine the accuracy log of MLT
    let al_mlt = if match_lengths_mode > 0 {
        table_mlt.accuracy_log
    } else {
        6
    };

    let last_tag_len = if offsets_mode + match_lengths_mode < 1 {
        n_fse_bytes_llt
    } else if match_lengths_mode < 1 {
        n_fse_bytes_cmot
    } else {
        n_fse_bytes_mlt
    };

    let src = &src[n_fse_bytes_mlt..];

    // update state
    let last_state = ZstdDecodingState {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceFseCode,
            tag_next: ZstdTag::ZstdBlockSequenceData,
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockSequenceFseCode.max_len(),
            tag_len: last_tag_len as u64,
        },
        encoded_data: EncodedDataCursor {
            byte_idx: byte_offset + (n_fse_bytes_llt + n_fse_bytes_cmot + n_fse_bytes_mlt) as u64,
            encoded_len: last_state.encoded_data.encoded_len,
        },
        bitstream_read_data: None,
        decoded_data: last_state.decoded_data,
        fse_data: None,
        literal_data: last_state.literal_data,
        repeated_offset: last_state.repeated_offset,
    };
    let byte_offset = last_state.encoded_data.byte_idx;

    ////////////////////////////////////////////////////////////////////////////
    ///// Sequence Section Part 3: Sequence Data (Instruction Bitstream)  //////
    ////////////////////////////////////////////////////////////////////////////

    // Reconstruct LLTV, CMOTV, and MLTV which specifies bit actions for a specific state
    let lltv = SequenceFixedStateActionTable::reconstruct_lltv();
    let cmotv = SequenceFixedStateActionTable::reconstruct_cmotv(CMOT_N);
    let mltv = SequenceFixedStateActionTable::reconstruct_mltv();

    // Decode sequence bitstream
    // TODO: too big for memory?
    let sequence_bitstream = src
        .iter()
        .rev()
        .flat_map(|v| {
            let mut bits = value_bits_le(*v);
            bits.reverse();
            bits
        })
        .collect::<Vec<u8>>();

    // Bitstream processing state values
    let _num_emitted: usize = 0;
    let n_sequence_data_bytes = src.len();
    let mut last_byte_idx: usize = 1;
    let mut current_byte_idx: usize = 1;
    let mut current_bit_idx: usize = 0;

    let mut padding_end_idx = 0;
    while sequence_bitstream[padding_end_idx] == 0 {
        padding_end_idx += 1;
    }

    let last_state = ZstdDecodingState {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceData,
            tag_next: if last_block {
                ZstdTag::Null
            } else {
                ZstdTag::BlockHeader
            },
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockSequenceData.max_len(),
            tag_len: n_sequence_data_bytes as u64,
        },
        encoded_data: EncodedDataCursor {
            byte_idx: byte_offset + n_sequence_data_bytes as u64,
            encoded_len: last_state.encoded_data.encoded_len,
        },
        bitstream_read_data: None,
        decoded_data: last_state.decoded_data,
        fse_data: None,
        literal_data: last_state.literal_data,
        repeated_offset: last_state.repeated_offset,
    };

    // Exclude the leading zero section
    while sequence_bitstream[current_bit_idx] == 0 {
        (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
    }
    // Exclude the sentinel 1-bit
    (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

    // Update accumulators
    if current_byte_idx > last_byte_idx {
        last_byte_idx = current_byte_idx;
    }

    // Now the actual data-bearing bitstream starts
    // The sequence bitstream is interleaved by 6 bit processing strands.
    // The interleaving order is: CMOVBits, MLVBits, LLVBits, LLFBits, MLFBits, CMOFBits
    let mut decoded_bitstring_values: Vec<(SequenceDataTag, u64)> = vec![];
    let mut raw_sequence_instructions: Vec<(usize, usize, usize)> = vec![]; // offset_state, match_length, literal_length
    let mut curr_instruction: [usize; 3] = [0, 0, 0];

    // Note: mode and order_idx produces 6 distinct decoding state
    let mut mode: usize = 1; // use 0 or 1 to denote whether bitstream produces data or next decoding state
    let mut order_idx: usize = 0; // use 0, 1, 2 to denote the order of decoded value within current mode

    let mut state_baselines: [usize; 3] = [0, 0, 0]; // 3 states for LL, ML, CMO
    let mut decoding_baselines: [usize; 3] = [0, 0, 0]; // 3 decoding bl for CMO, ML, LL

    let data_tags = [
        SequenceDataTag::CookedMatchOffsetValue,
        SequenceDataTag::MatchLengthValue,
        SequenceDataTag::LiteralLengthValue,
        SequenceDataTag::LiteralLengthFse,
        SequenceDataTag::MatchLengthFse,
        SequenceDataTag::CookedMatchOffsetFse,
    ];
    let next_nb_to_read_for_states: [usize; 3] =
        [al_llt as usize, al_mlt as usize, al_cmot as usize]; // Obtained from accuracy log
    let next_nb_to_read_for_values: [usize; 3] = [0, 0, 0];
    let mut nb_switch = [next_nb_to_read_for_values, next_nb_to_read_for_states];
    let v_tables = [cmotv, mltv, lltv];
    let f_tables = [llt, mlt, cmot];

    let mut is_init = true;
    let mut nb = nb_switch[mode][order_idx];
    let bitstream_end_bit_idx = n_sequence_data_bytes * N_BITS_PER_BYTE;
    let mut table_kind;
    let mut last_states: [u64; 3] = [0, 0, 0];
    let mut last_symbols: [u64; 3] = [0, 0, 0];
    let mut current_decoding_state;
    let mut tail_holding_bit = false;

    while current_bit_idx + nb <= bitstream_end_bit_idx {
        let bitstring_value =
            be_bits_to_value(&sequence_bitstream[current_bit_idx..(current_bit_idx + nb)]);
        let curr_baseline;

        if mode > 0 {
            // For the initial baseline determination, ML and CMO positions are flipped.
            if is_init {
                order_idx = [0, 2, 1][order_idx];
            }

            let new_decoded = (data_tags[mode * 3 + order_idx], bitstring_value);
            decoded_bitstring_values.push(new_decoded);

            current_decoding_state = (mode * 3 + order_idx) as u64;

            table_kind = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_kind as u64
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_kind as u64
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_kind as u64
                }
            };

            // FSE state update step
            curr_baseline = state_baselines[order_idx];
            let new_state = (curr_baseline as u64) + bitstring_value;
            last_states[order_idx] = new_state;
            let new_state_params = f_tables[order_idx]
                .get(&new_state)
                .expect("State should exist.");
            let state_symbol = new_state_params.0;
            last_symbols[order_idx] = state_symbol;

            let value_idx = 3 - order_idx - 1;

            // Update baseline and nb for next FSE state transition
            state_baselines[order_idx] = new_state_params.1 as usize;
            nb_switch[1][order_idx] = new_state_params.2 as usize;

            // Update baseline and nb for next value decoding
            decoding_baselines[value_idx] = v_tables[value_idx].states_to_actions
                [state_symbol as usize]
                .1
                 .0 as usize;
            nb_switch[0][value_idx] = v_tables[value_idx].states_to_actions[state_symbol as usize]
                .1
                 .1 as usize;

            // Flip back the idx for first step
            if is_init {
                order_idx = [0, 2, 1][order_idx];
            }
        } else {
            let new_decoded = (data_tags[mode * 3 + order_idx], bitstring_value);
            decoded_bitstring_values.push(new_decoded);

            current_decoding_state = (mode * 3 + order_idx) as u64;

            table_kind = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_kind as u64
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_kind as u64
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_kind as u64
                }
            };

            // Value decoding step
            curr_baseline = decoding_baselines[order_idx];
            let new_value = (curr_baseline as u64) + bitstring_value;
            curr_instruction[order_idx] = new_value as usize;
        }

        // bitstream witness row data
        let from_bit_idx = current_bit_idx.rem_euclid(8);
        let to_bit_idx = if nb > 0 {
            from_bit_idx + (nb - 1)
        } else {
            from_bit_idx
        };

        // When the range of a multi-byte read operation from the bitstream covers an entire byte,
        // a separate row needs to be added for each of such byte to ensure continuity of the value
        // accumulators. These compensating rows have is_nil=true. At most, two bytes can be
        // entirely covered by a bitstream read operation.
        let multi_byte_boundaries: [usize; 3] = [15, 23, 31];
        let mut skipped_bits = 0usize;

        for boundary in multi_byte_boundaries {
            if to_bit_idx >= boundary {
                // TODO: increase 8 times, can be optimized
                // Skip over covered bytes for byte and bit index
                for _ in 0..N_BITS_PER_BYTE {
                    (current_byte_idx, current_bit_idx) =
                        increment_idx(current_byte_idx, current_bit_idx);
                }
                // Increment accumulators for nil row
                if current_byte_idx > last_byte_idx && current_byte_idx <= n_sequence_data_bytes {
                    last_byte_idx = current_byte_idx;
                }
                skipped_bits += N_BITS_PER_BYTE;

                match to_bit_idx {
                    15 => 8,
                    16..=23 => 16,
                    24..=31 => 24,
                    v => unreachable!(
                        "unexpected bit_index_end={:?} in (table={:?}, update_f?={:?}) (bit_index_start={:?}, bitstring_len={:?})",
                        v, table_kind, (current_decoding_state >= 3), from_bit_idx, to_bit_idx - from_bit_idx + 1,
                    ),
                };
            }
        }

        // Update all variables that indicate current decoding states
        order_idx += 1;
        if mode > 0 {
            if order_idx > 2 {
                is_init = false;
                mode = 0; // switch to data mode
                order_idx = 0;
            }
        } else if order_idx > 2 {
            mode = 1; // switch to FSE mode
            order_idx = 0;

            // Three elements (MO, ML and LL) are all decoded. Add the instruction.
            let new_instruction = (
                curr_instruction[0],
                curr_instruction[1],
                curr_instruction[2],
            );

            raw_sequence_instructions.push(new_instruction);
        }

        let next_nb = if is_init {
            // On the first step, ML and CMO are flipped
            let true_idx = [0, 2, 1][order_idx];
            nb_switch[mode][true_idx]
        } else {
            nb_switch[mode][order_idx]
        };

        // Adjust the end position of the current read operation:
        // If the next operation reads 0 bits, the ending bit position should stay on
        // the last bit, instead of incrementing to the next position. When the nb=0 streak breaks,
        // the held off position is released.
        if nb > 0 && next_nb > 0 {
            for _ in 0..(nb - skipped_bits) {
                (current_byte_idx, current_bit_idx) =
                    increment_idx(current_byte_idx, current_bit_idx);
            }
        } else if nb > 0 && next_nb == 0 {
            tail_holding_bit = true;
            for _ in 0..(nb - skipped_bits - 1) {
                (current_byte_idx, current_bit_idx) =
                    increment_idx(current_byte_idx, current_bit_idx);
            }
        } else if nb == 0 && next_nb > 0 && tail_holding_bit {
            (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
            tail_holding_bit = false;
        }

        if current_byte_idx > last_byte_idx && current_byte_idx <= n_sequence_data_bytes {
            last_byte_idx = current_byte_idx;
        }

        // Update the next nb for the next read operation
        nb = next_nb;
    }

    // Process raw sequence instructions and execute to acquire the original input
    let mut current_literal_pos: usize = 0;

    let literals = &last_state.literal_data;
    let mut decoded_bytes = last_state.decoded_data;
    let mut repeated_offset = last_state.repeated_offset;

    for inst in raw_sequence_instructions.iter() {
        let actual_offset = if inst.0 > 3 {
            inst.0 - 3
        } else {
            let repeat_idx = inst.0;
            if inst.2 == 0 {
                if repeat_idx == 3 {
                    repeated_offset[0] - 1
                } else {
                    repeated_offset[repeat_idx]
                }
            } else {
                repeated_offset[repeat_idx - 1]
            }
        };

        let &(_cooked_match_offset, match_length, literal_length) = inst;

        let new_literal_pos = current_literal_pos + literal_length;
        if new_literal_pos > current_literal_pos {
            let r = current_literal_pos..new_literal_pos;
            decoded_bytes.extend(literals[r].iter().map(|&v| v as u8));
        }

        let match_pos = decoded_bytes.len() - actual_offset;
        if match_length > 0 {
            let r = match_pos..(match_length + match_pos);
            // TODO: optimize this vec?
            let matched_and_repeated_bytes = if match_length <= actual_offset {
                Vec::from(&decoded_bytes[r])
            } else {
                let l = match_length;
                let r_prime = match_pos..decoded_bytes.len();
                let matched_bytes = Vec::from(&decoded_bytes[r_prime]);
                matched_bytes.iter().cycle().take(l).copied().collect()
            };
            decoded_bytes.extend_from_slice(matched_and_repeated_bytes.as_slice());
        }
        current_literal_pos = new_literal_pos;

        // Update repeated offset
        if inst.0 > 3 {
            repeated_offset[2] = repeated_offset[1];
            repeated_offset[1] = repeated_offset[0];
            repeated_offset[0] = inst.0 - 3;
        } else {
            let mut repeat_idx = inst.0;
            if inst.2 == 0 {
                repeat_idx += 1;
            }

            if repeat_idx == 2 {
                repeated_offset.swap(1, 0);
            } else if repeat_idx == 3 {
                let result = repeated_offset[2];
                repeated_offset[2] = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else if repeat_idx == 4 {
                let result = repeated_offset[0] - 1;
                assert!(result > 0, "corruptied data");
                repeated_offset[2] = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else {
                // repeat 1
            }
        };
    }

    // Add remaining literal bytes
    if current_literal_pos < literals.len() {
        let r = current_literal_pos..;
        decoded_bytes.extend(literals[r].iter().map(|&v| v as u8));
    }

    //println!("offset after seq body {} of block {}", byte_offset as usize + n_sequence_data_bytes, block_idx);

    Ok(ZstdDecodingState {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceData,
            tag_next: if last_block {
                ZstdTag::Null
            } else {
                ZstdTag::BlockHeader
            },
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockSequenceData.max_len(),
            tag_len: n_sequence_data_bytes as u64,
        },
        encoded_data: EncodedDataCursor {
            byte_idx: byte_offset + n_sequence_data_bytes as u64,
            encoded_len: last_state.encoded_data.encoded_len,
        },
        bitstream_read_data: None,
        decoded_data: decoded_bytes,
        fse_data: None,
        literal_data: Vec::new(),
        repeated_offset,
    })
}

fn process_block_zstd_literals_header(
    src: &[u8],
    block_idx: u64,
    last_state: ZstdDecodingState,
) -> Result<(ZstdDecodingState, usize)> {
    let byte_offset = last_state.encoded_data.byte_idx;
    let src = &src[byte_offset as usize..];

    let literals_block_type = BlockType::from(src[0] & 0x3);
    let size_format = (src[0] >> 2) & 3;

    let [n_bits_fmt, n_bits_regen, n_bytes_header]: [usize; 3] = match literals_block_type {
        BlockType::RawBlock => match size_format {
            0b00 | 0b10 => [1, 5, 1],
            0b01 => [2, 12, 2],
            0b11 => [2, 20, 3],
            _ => unreachable!("size_format out of bound"),
        },
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    assert!(src.len() > n_bytes_header);
    let lh_bytes = &src[..n_bytes_header];

    // Bits for representing regenerated_size and compressed_size
    let sizing_bits: Vec<u8> = lh_bytes
        .iter()
        .flat_map(|b| value_bits_le(*b))
        .skip(2 + n_bits_fmt)
        .collect();

    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]) as usize;
    let tag_next = match literals_block_type {
        BlockType::RawBlock => ZstdTag::ZstdBlockLiteralsRawBytes,
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    Ok((
        ZstdDecodingState {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockLiteralsHeader,
                tag_next,
                block_idx,
                max_tag_len: ZstdTag::ZstdBlockLiteralsHeader.max_len(),
                tag_len: n_bytes_header as u64,
            },
            encoded_data: EncodedDataCursor {
                byte_idx: byte_offset + n_bytes_header as u64,
                encoded_len: last_state.encoded_data.encoded_len,
            },
            decoded_data: last_state.decoded_data,
            bitstream_read_data: None,
            fse_data: None,
            literal_data: Vec::new(),
            repeated_offset: last_state.repeated_offset,
        },
        regen_size,
    ))
}

/// Process a slice of bytes into decompression circuit witness rows
pub fn process(src: &[u8]) -> Result<ZstdDecodingState> {
    // // FrameHeaderDescriptor and FrameContentSize
    let (_frame_content_size, mut last_state) =
        process_frame_header(src, ZstdDecodingState::init(src.len()))?;
    //println!("offset after frame header {} (fcs {})", last_state.encoded_data.byte_idx, frame_content_size);
    let mut block_idx: u64 = 1;
    loop {
        let (block_state, block_info) = process_block(src, block_idx, last_state)?;
        let offset = block_state.encoded_data.byte_idx as usize;
        //log::debug!("processed block={:?}: offset={:?}", block_idx, offset);
        last_state = block_state;

        if block_info.is_last_block {
            assert!(offset >= src.len());
            break;
        } else {
            block_idx += 1;
        }
    }

    Ok(last_state)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    /// re-export constants in zstd-encoder
    use zstd_encoder::N_BLOCK_SIZE_TARGET;

    use zstd_encoder::{init_zstd_encoder as init_zstd_encoder_n, zstd};

    /// Zstd encoder configuration
    fn init_zstd_encoder(
        target_block_size: Option<u32>,
    ) -> zstd::stream::Encoder<'static, Vec<u8>> {
        init_zstd_encoder_n(target_block_size.unwrap_or(N_BLOCK_SIZE_TARGET))
    }

    fn test_processing(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        use super::*;
        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder.window_log(24)?;
            encoder.set_pledged_src_size(Some(data.len() as u64))?;

            encoder.write_all(data)?;
            encoder.finish()?
        };

        let state = process(&compressed).unwrap();
        Ok(state.decoded_data)
    }

    fn read_sample() -> Result<impl Iterator<Item = Vec<u8>>, std::io::Error> {
        let mut batch_files = fs::read_dir("./data/test_batches")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();
        Ok(batch_files
            .into_iter()
            .map(fs::read_to_string)
            .filter_map(|data| data.ok())
            .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data")))
    }

    #[test]
    fn test_zstd_witness_processing_batch_data() -> Result<(), std::io::Error> {
        for raw_input_bytes in read_sample()? {
            let decoded_bytes = test_processing(&raw_input_bytes)?;

            assert!(raw_input_bytes == decoded_bytes);
        }

        Ok(())
    }

    #[test]
    fn test_zstd_witness_processing_rle_data() -> Result<(), std::io::Error> {
        for mut raw_input_bytes in read_sample()? {
            // construct rle block and long-ref
            if raw_input_bytes.len() < 128 * 1024 {
                let cur = raw_input_bytes.clone();
                // construct an rle
                raw_input_bytes.resize(256 * 1024, 42u8);
                // then we can have a long-distance ref
                raw_input_bytes.extend(cur);
            }

            let decoded_bytes = test_processing(&raw_input_bytes)?;

            assert!(raw_input_bytes == decoded_bytes);
        }

        Ok(())
    }
}
