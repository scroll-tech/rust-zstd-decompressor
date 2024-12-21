
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
        .get(0)
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
            .iter().take(fcs_tag_len).rev()
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
        }
    ))
}

#[derive(Debug, Clone)]
pub struct AggregateBlockResult {
    pub decoded_state: ZstdDecodingState,
    pub block_info: BlockInfo,
    pub sequence_info: SequenceInfo,
    pub fse_aux_tables: [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
    pub address_table_rows: Vec<AddressTableRow>,
    pub sequence_exec_result: SequenceExecResult,
    pub repeated_offset: [usize; 3], // repeated offsets are carried forward between blocks.
}

fn process_block(
    src: &[u8],
    block_idx: u64,
    last_state: ZstdDecodingState,
) -> Result<(ZstdDecodingState, BlockInfo)> {

    let (last_state, block_info) =
        process_block_header(src, block_idx, last_state)?;

    let last_state = match block_info.block_type {
        BlockType::ZstdCompressedBlock => process_block_zstd(
            src,
            block_idx,
            last_state,
            block_info.block_len,
            block_info.is_last_block,
        ),
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

#[derive(Debug, Default, Clone)]
pub struct SequenceExecResult {
    pub exec_trace: Vec<SequenceExec>,
    pub recovered_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BlockProcessingResult {
    pub sequence_info: SequenceInfo,
    // pub fse_aux_tables: [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
    // pub address_table_rows: Vec<AddressTableRow>,
    // TODO: try to process sequence on the fly
    pub sequence_exec_result: SequenceExecResult,
    pub repeated_offset: [usize; 3], // repeated offsets are carried forward between blocks
    pub regen_size: u64,
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
    let src = &src[byte_offset..];

    let expected_end_offset = byte_offset + block_size;

    // 1-5 bytes LiteralSectionHeader
    let (last_state, regen_size) = process_block_zstd_literals_header(src, block_idx, last_state)?;

    // Literal body
    let byte_offset = last_state.encoded_data.byte_idx as usize;
    let src = &src[byte_offset..];

    let literal_data = src[..regen_size].iter().map(|b|*b as u64).collect();

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

    // let LiteralsBlockResult {
    //     offset: byte_offset,
    //     witness_rows: rows,
    //     literals,
    // } = {
    //     let last_row = rows.last().cloned().unwrap();
    //     let multiplier =
    //         (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    //     let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;
    //     let tag = ZstdTag::ZstdBlockLiteralsRawBytes;
    //     let tag_next = ZstdTag::ZstdBlockSequenceHeader;
    //     let literals = src[byte_offset..(byte_offset + regen_size)].to_vec();
    //     let tag_rlc_iter = literals.iter().scan(Value::known(F::zero()), |acc, &byte| {
    //         *acc = *acc * randomness + Value::known(F::from(byte as u64));
    //         Some(*acc)
    //     });
    //     let tag_rlc = tag_rlc_iter.clone().last().expect("Literals must exist.");

    //     LiteralsBlockResult {
    //         offset: byte_offset + regen_size,
    //         witness_rows: literals
    //             .iter()
    //             .zip(tag_rlc_iter)
    //             .enumerate()
    //             .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
    //                 state: ZstdState {
    //                     tag,
    //                     tag_next,
    //                     block_idx,
    //                     max_tag_len: tag.max_len(),
    //                     tag_len: regen_size as u64,
    //                     tag_idx: (i + 1) as u64,
    //                     is_tag_change: i == 0,
    //                     tag_rlc,
    //                     tag_rlc_acc,
    //                 },
    //                 encoded_data: EncodedData {
    //                     byte_idx: (byte_offset + i + 1) as u64,
    //                     encoded_len: last_row.encoded_data.encoded_len,
    //                     value_byte,
    //                     value_rlc,
    //                     reverse: false,
    //                     ..Default::default()
    //                 },
    //                 decoded_data: DecodedData {
    //                     decoded_len: last_row.decoded_data.decoded_len,
    //                 },
    //                 bitstream_read_data: BitstreamReadRow::default(),
    //                 fse_data: FseDecodingRow::default(),
    //             })
    //             .collect::<Vec<_>>(),
    //         literals: literals.iter().map(|b| *b as u64).collect::<Vec<u64>>(),
    //     }
    // };

    let last_state = process_sequences(
        src, 
        block_idx, 
        expected_end_offset, 
        last_state, 
        last_block
    )?;

    // let SequencesProcessingResult {
    //     offset,
    //     witness_rows: rows,
    //     fse_aux_tables,
    //     address_table_rows,
    //     original_bytes,
    //     sequence_info,
    //     sequence_exec,
    //     repeated_offset,
    // } = process_sequences::<F>(
    //     src,
    //     decoded_bytes,
    //     block_idx,
    //     byte_offset,
    //     expected_end_offset,
    //     literals.clone(),
    //     last_row,
    //     last_block,
    //     randomness,
    //     repeated_offset,
    // );

    // sanity check:
    assert_eq!(
        last_state.encoded_data.byte_idx as usize, expected_end_offset,
        "end offset after tag=SequencesData mismatch"
    );

    Ok(last_state)

}

#[derive(Debug, Clone)]
pub struct SequencesProcessingResult {
    pub offset: usize,
//    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub fse_aux_tables: [FseAuxiliaryTableData; 3], // LLT, MLT, CMOT
    pub address_table_rows: Vec<AddressTableRow>,   // Parsed sequence instructions
    pub original_bytes: Vec<u8>,                    // Recovered original input
    pub sequence_info: SequenceInfo,
    pub sequence_exec: Vec<SequenceExec>,
    pub repeated_offset: [usize; 3],
}

#[allow(clippy::too_many_arguments)]
fn process_sequences(
    src: &[u8],
    block_idx: u64,
    expected_seq_size: usize,
    last_state: ZstdDecodingState,
    last_block: bool,
) -> Result<ZstdDecodingState> {
    let encoded_len = last_state.encoded_data.encoded_len;
    let byte_offset = last_state.encoded_data.byte_idx;
    let src = &src[byte_offset as usize..];

    //////////////////////////////////////////////////////
    ///// Sequence Section Part 1: Sequence Header  //////
    //////////////////////////////////////////////////////

    assert!(src.len() >= 1, "First byte of sequence header must exist.");
    let byte0 = src[0];
    assert!(byte0 > 0u8, "Sequences can't be of 0 length");

    let (num_of_sequences, num_sequence_header_bytes) = if byte0 < 128 {
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

    assert!(src.len() >= num_sequence_header_bytes, "Compression mode byte must exist.");
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
    let compression_mode = [
        literal_lengths_mode > 0,
        offsets_mode > 0,
        match_lengths_mode > 0,
    ];

    let is_all_predefined_fse = literal_lengths_mode + offsets_mode + match_lengths_mode < 1;

    // Add witness rows for the sequence header
    // let sequence_header_start_offset = byte_offset;
    // let sequence_header_end_offset = byte_offset + num_sequence_header_bytes;

    // let tag_rlc_iter = src[sequence_header_start_offset..sequence_header_end_offset]
    //     .iter()
    //     .scan(Value::known(F::zero()), |acc, &byte| {
    //         *acc = *acc * randomness + Value::known(F::from(byte as u64));
    //         Some(*acc)
    //     });
    // let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");

    // let header_rows = src[sequence_header_start_offset..sequence_header_end_offset]
    //     .iter()
    //     .zip(tag_rlc_iter)
    //     .enumerate()
    //     .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
    //         state: ZstdState {
    //             tag: ZstdTag::ZstdBlockSequenceHeader,
    //             tag_next: if is_all_predefined_fse {
    //                 ZstdTag::ZstdBlockSequenceData
    //             } else {
    //                 ZstdTag::ZstdBlockSequenceFseCode
    //             },
    //             block_idx,
    //             max_tag_len: ZstdTag::ZstdBlockSequenceHeader.max_len(),
    //             tag_len: num_sequence_header_bytes as u64,
    //             tag_idx: (i + 1) as u64,
    //             is_tag_change: i == 0,
    //             tag_rlc,
    //             tag_rlc_acc,
    //         },
    //         encoded_data: EncodedData {
    //             byte_idx: (sequence_header_start_offset + i + 1) as u64,
    //             encoded_len: last_row.encoded_data.encoded_len,
    //             value_byte,
    //             value_rlc,
    //             reverse: false,
    //             ..Default::default()
    //         },
    //         decoded_data: DecodedData {
    //             decoded_len: last_row.decoded_data.decoded_len,
    //         },
    //         bitstream_read_data: BitstreamReadRow::default(),
    //         fse_data: FseDecodingRow::default(),
    //     })
    //     .collect::<Vec<_>>();

    // witness_rows.extend_from_slice(&header_rows);

    /////////////////////////////////////////////////
    ///// Sequence Section Part 2: FSE Tables  //////
    /////////////////////////////////////////////////
    // let byte_offset = sequence_header_end_offset;
    // let fse_starting_byte_offset = byte_offset;
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
    let (n_fse_bytes_cmot, table_cmot) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::MOT,
        offsets_mode < 2,
    )
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
    let sequence_bitstream = src[..expected_seq_size]
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
    let n_sequence_data_bytes = expected_seq_size;
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
    let mut seq_idx: usize = 0;
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
    let bitstream_end_bit_idx = n_sequence_data_bytes as usize * N_BITS_PER_BYTE;
    let mut table_kind;
    let mut table_size;
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

            if order_idx < 1 {
                seq_idx += 1;
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
            table_size = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_size
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_size
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_size
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
            table_size = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_size
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_size
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_size
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
        let multi_byte_boundaries: [usize; 2] = [15, 23];
        let mut skipped_bits = 0usize;

        for boundary in multi_byte_boundaries {
            if to_bit_idx >= boundary {
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

                let wrap_by = match to_bit_idx {
                    15 => 8,
                    16..=23 => 16,
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
    let mut literal_len_acc: usize = 0;

    let mut seq_exec_info: Vec<SequenceExec> = vec![];
    let mut current_literal_pos: usize = 0;

    let literals = &last_state.literal_data;
    let mut decoded_bytes = last_state.decoded_data;
    let mut repeated_offset = last_state.repeated_offset;

    for (idx, inst) in raw_sequence_instructions.iter().enumerate() {
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

        literal_len_acc += inst.2;
        let &(cooked_match_offset, match_length, literal_length) = inst;

        let new_literal_pos = current_literal_pos + literal_length;
        if new_literal_pos > current_literal_pos {
            let r = current_literal_pos..new_literal_pos;
            decoded_bytes.extend(literals[r].iter().map(|&v| v as u8));
        }

        let match_pos = decoded_bytes.len() - actual_offset;
        if match_length > 0 {
            let r = match_pos..(match_length as usize + match_pos);
            // TODO: optimize this vec?
            let matched_and_repeated_bytes = if match_length <= actual_offset {
                Vec::from(&decoded_bytes[r])
            } else {
                let l = match_length as usize;
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
        repeated_offset: repeated_offset,
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
    let sizing_bits : Vec<u8> = lh_bytes.iter()
    .flat_map(|b|value_bits_le(*b))
    .skip(2 + n_bits_fmt)
    .collect();

    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]) as usize;
    let tag_next = match literals_block_type {
        BlockType::RawBlock => ZstdTag::ZstdBlockLiteralsRawBytes,
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    Ok(
        (ZstdDecodingState {
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
        regen_size)
    )

}

/// Result for processing multiple blocks from compressed data
// #[derive(Debug, Clone)]
// pub struct MultiBlockProcessResult<F> {
//     pub witness_rows: Vec<ZstdWitnessRow<F>>,
//     pub literal_bytes: Vec<Vec<u64>>, // literals
//     pub fse_aux_tables: Vec<FseAuxiliaryTableData>,
//     pub block_info_arr: Vec<BlockInfo>,
//     pub sequence_info_arr: Vec<SequenceInfo>,
//     pub address_table_rows: Vec<Vec<AddressTableRow>>,
//     pub sequence_exec_results: Vec<SequenceExecResult>,
// }

/// Process a slice of bytes into decompression circuit witness rows
pub fn process(src: &[u8]) -> Result<ZstdDecodingState> {
    // let mut witness_rows = vec![];
    // let mut decoded_bytes: Vec<u8> = vec![];
    // let mut literals: Vec<Vec<u64>> = vec![];
    // let mut fse_aux_tables: Vec<FseAuxiliaryTableData> = vec![];
    // let mut block_info_arr: Vec<BlockInfo> = vec![];
    // let mut sequence_info_arr: Vec<SequenceInfo> = vec![];
    // let mut address_table_arr: Vec<Vec<AddressTableRow>> = vec![];
    // let mut sequence_exec_info_arr: Vec<SequenceExecResult> = vec![];

    // // FrameHeaderDescriptor and FrameContentSize
    // let (mut byte_offset, rows) = process_frame_header::<F>(
    //     src,
    //     0, // frame header starts at offset=0
    //     &ZstdWitnessRow::init(src.len()),
    //     randomness,
    // );
    // witness_rows.extend_from_slice(&rows);

    let mut block_idx: u64 = 1;
    let mut last_state = ZstdDecodingState::init(src.len());
    loop {
        let (block_state, block_info) = process_block(
            src,
            block_idx,
            last_state,
        )?;
        let offset = block_state.encoded_data.byte_idx as usize;
        log::debug!("processed block={:?}: offset={:?}", block_idx, offset);
        block_idx += 1;
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
    use std::{fs, fs::File, io::Write};

    /// re-export constants in zstd-encoder
    use zstd_encoder::N_BLOCK_SIZE_TARGET;

    use zstd_encoder::{init_zstd_encoder as init_zstd_encoder_n, zstd};

    /// Zstd encoder configuration
    fn init_zstd_encoder(
        target_block_size: Option<u32>,
    ) -> zstd::stream::Encoder<'static, Vec<u8>> {
        init_zstd_encoder_n(target_block_size.unwrap_or(N_BLOCK_SIZE_TARGET))
    }

    /// Encode input bytes by using the default encoder.
    fn zstd_encode(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = init_zstd_encoder(None);
        encoder
            .set_pledged_src_size(Some(bytes.len() as u64))
            .expect("infallible");
        encoder.write_all(bytes).expect("infallible");
        encoder.finish().expect("infallible")
    }

    // #[test]
    // #[ignore]
    // fn compression_ratio() -> Result<(), std::io::Error> {
    //     use csv::WriterBuilder;

    //     let get_compression_ratio = |data: &[u8]| -> Result<(u64, u64, H256), std::io::Error> {
    //         let raw_len = data.len();
    //         let compressed = {
    //             // compression level = 0 defaults to using level=3, which is zstd's default.
    //             let mut encoder = init_zstd_encoder(None);

    //             // set source length, which will be reflected in the frame header.
    //             encoder.set_pledged_src_size(Some(raw_len as u64))?;

    //             encoder.write_all(data)?;
    //             encoder.finish()?
    //         };
    //         let hash = keccak256(&compressed);
    //         let compressed_len = compressed.len();
    //         Ok((raw_len as u64, compressed_len as u64, hash.into()))
    //     };

    //     let mut batch_files = fs::read_dir("./data")?
    //         .map(|entry| entry.map(|e| e.path()))
    //         .collect::<Result<Vec<_>, std::io::Error>>()?;
    //     batch_files.sort();

    //     let batches = batch_files
    //         .iter()
    //         .map(fs::read_to_string)
    //         .filter_map(|data| data.ok())
    //         .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
    //         .collect::<Vec<Vec<u8>>>();

    //     let file = File::create("modified-ratio.csv")?;
    //     let mut writer = WriterBuilder::new().from_writer(file);

    //     // Write headers to CSV
    //     writer.write_record(["ID", "Len(input)", "Compression Ratio"])?;

    //     // Test and store results in CSV
    //     for (i, batch) in batches.iter().enumerate() {
    //         let (raw_len, compr_len, keccak_hash) = get_compression_ratio(batch)?;
    //         println!(
    //             "batch{:0>3}, raw_size={:6}, compr_size={:6}, compr_keccak_hash={:64x}",
    //             i, raw_len, compr_len, keccak_hash
    //         );

    //         // Write input and result to CSV
    //         let compr_ratio = raw_len as f64 / compr_len as f64;
    //         writer.write_record(&[i.to_string(), raw_len.to_string(), compr_ratio.to_string()])?;
    //     }

    //     // Flush the CSV writer
    //     writer.flush()?;

    //     Ok(())
    // }

    #[test]
    fn test_zstd_witness_processing_batch_data() -> Result<(), std::io::Error> {
        use super::*;

        let mut batch_files = fs::read_dir("./data/test_batches")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();
        let batches = batch_files
            .iter()
            .map(fs::read_to_string)
            .filter_map(|data| data.ok())
            .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
            .collect::<Vec<Vec<u8>>>();

        for raw_input_bytes in batches.into_iter() {
            let compressed = {
                // compression level = 0 defaults to using level=3, which is zstd's default.
                let mut encoder = init_zstd_encoder(None);

                // set source length, which will be reflected in the frame header.
                encoder.set_pledged_src_size(Some(raw_input_bytes.len() as u64))?;

                encoder.write_all(&raw_input_bytes)?;
                encoder.finish()?
            };

            let state = process(&compressed).unwrap();

            let decoded_bytes = state.decoded_data;

            assert!(raw_input_bytes == decoded_bytes);
        }

        Ok(())
    }
}
