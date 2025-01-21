use strum_macros::EnumIter;

pub use crate::fse::{FseAuxiliaryTableData, FseTableRow};

#[derive(Debug, Default, Clone, Copy)]
pub enum BlockType {
    #[default]
    RawBlock = 0,
    RleBlock,
    ZstdCompressedBlock,
    Reserved,
}

impl From<u8> for BlockType {
    fn from(src: u8) -> Self {
        match src {
            0 => Self::RawBlock,
            1 => Self::RleBlock,
            2 => Self::ZstdCompressedBlock,
            3 => Self::Reserved,
            _ => unreachable!("BlockType is 2 bits"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockInfo {
    pub block_idx: usize,
    pub block_type: BlockType,
    pub block_len: usize,
    pub is_last_block: bool,
    pub regen_size: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SequenceInfo {
    pub block_idx: usize,
    pub num_sequences: usize,
    pub compression_mode: [bool; 3],
}

/// The type for indicate each range in output bytes by sequence execution
#[derive(Debug, Clone)]
pub enum SequenceExecInfo {
    LiteralCopy(std::ops::Range<usize>),
    BackRef(std::ops::Range<usize>),
}

/// The type to describe an execution: (instruction_id, exec_info)
#[derive(Debug, Clone)]
pub struct SequenceExec(pub usize, pub SequenceExecInfo);

/// The type of Lstream.
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LstreamNum {
    /// Lstream 1.
    Lstream1 = 0,
    /// Lstream 2.
    Lstream2,
    /// Lstream 3.
    Lstream3,
    /// Lstream 4.
    Lstream4,
}

impl From<LstreamNum> for usize {
    fn from(value: LstreamNum) -> Self {
        value as usize
    }
}
impl From<usize> for LstreamNum {
    fn from(value: usize) -> LstreamNum {
        match value {
            0 => LstreamNum::Lstream1,
            1 => LstreamNum::Lstream2,
            2 => LstreamNum::Lstream3,
            3 => LstreamNum::Lstream4,
            _ => unreachable!("Wrong stream_idx"),
        }
    }
}

/// Various tags that we can decode from a zstd encoded data.
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, Hash)]
pub enum ZstdTag {
    /// Null is reserved for padding rows.
    Null = 0,
    /// The frame header's descriptor.
    FrameHeaderDescriptor,
    /// The frame's content size.
    FrameContentSize,
    /// The block's header.
    BlockHeader,
    /// The block's content (for raw / rle)
    BlockContent,
    /// Zstd block's literals header.
    ZstdBlockLiteralsHeader,
    /// Zstd blocks might contain raw bytes.
    ZstdBlockLiteralsRawBytes,
    /// Beginning of sequence section.
    ZstdBlockSequenceHeader,
    /// Zstd block's FSE code.
    ZstdBlockSequenceFseCode,
    /// sequence bitstream for recovering instructions
    ZstdBlockSequenceData,
}

impl ZstdTag {
    /// Whether this tag is a part of block or not.
    pub fn is_block(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::BlockContent => true,
            Self::ZstdBlockLiteralsHeader => true,
            Self::ZstdBlockLiteralsRawBytes => true,
            Self::ZstdBlockSequenceHeader => true,
            Self::ZstdBlockSequenceFseCode => true,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// Whether this tag is processed in back-to-front order.
    pub fn is_reverse(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::BlockContent => false,
            Self::ZstdBlockLiteralsHeader => false,
            Self::ZstdBlockLiteralsRawBytes => false,
            Self::ZstdBlockSequenceHeader => false,
            Self::ZstdBlockSequenceFseCode => false,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// The maximum number of bytes that can be taken by this tag.
    pub fn max_len(&self) -> u64 {
        match self {
            Self::Null => 0,
            Self::FrameHeaderDescriptor => 1,
            Self::FrameContentSize => 8,
            Self::BlockHeader => 3,
            Self::BlockContent => (1 << 8) - 1, // 128kB
            // as per spec, should be 5. But given that our encoder does not compress literals, it
            // is 3.
            Self::ZstdBlockLiteralsHeader => 3,
            Self::ZstdBlockLiteralsRawBytes => (1 << 17) - 1,
            Self::ZstdBlockSequenceHeader => 4,
            Self::ZstdBlockSequenceFseCode => 128,
            Self::ZstdBlockSequenceData => (1 << 17) - 1,
        }
    }
}

impl From<ZstdTag> for usize {
    fn from(value: ZstdTag) -> Self {
        value as usize
    }
}

/// FSE table variants that we observe in the sequences section.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum FseTableKind {
    /// Literal length FSE table.
    LLT = 1,
    /// Match offset FSE table.
    MOT,
    /// Match length FSE table.
    MLT,
}

impl std::fmt::Display for ZstdTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Null => "null",
                Self::FrameHeaderDescriptor => "FrameHeaderDescriptor",
                Self::FrameContentSize => "FrameContentSize",
                Self::BlockHeader => "BlockHeader",
                Self::BlockContent => "BlockContent",
                Self::ZstdBlockLiteralsHeader => "ZstdBlockLiteralsHeader",
                Self::ZstdBlockLiteralsRawBytes => "ZstdBlockLiteralsRawBytes",
                Self::ZstdBlockSequenceHeader => "ZstdBlockSequenceHeader",
                Self::ZstdBlockSequenceFseCode => "ZstdBlockSequenceFseCode",
                Self::ZstdBlockSequenceData => "ZstdBlockSequenceData",
            }
        )
    }
}

#[derive(Clone, Debug)]
pub struct ZstdState {
    pub tag: ZstdTag,
    pub tag_next: ZstdTag,
    pub block_idx: u64,
    pub max_tag_len: u64,
    pub tag_len: u64,
}

impl Default for ZstdState {
    fn default() -> Self {
        Self {
            tag: ZstdTag::Null,
            tag_next: ZstdTag::FrameHeaderDescriptor,
            block_idx: 0,
            max_tag_len: 0,
            tag_len: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EncodedDataCursor {
    /// the index for the next byte should be decoded
    pub byte_idx: u64,
    /// the total size of encoded (src) bytes, constant in
    /// the decoding process
    pub encoded_len: u64,
    // pub reverse: bool,
    // pub reverse_idx: u64,
    // pub reverse_len: u64,
}

/// Last FSE decoding state for decoding
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseDecodingState {
    /// The FSE table that is being decoded. Possible values are:
    /// - LLT = 1, MOT = 2, MLT = 3
    pub table_kind: u64,
    /// The number of states in the FSE table. table_size == 1 << AL, where AL is the accuracy log
    /// of the FSE table.
    pub table_size: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u64,
    /// During FSE table decoding, keep track of the number of symbol emitted
    pub num_emitted: u64,
    /// The value decoded as per variable bit-packing.
    pub value_decoded: u64,
    /// An accumulator of the number of states allocated to each symbol as we decode the FSE table.
    /// This is the normalised probability for the symbol.
    pub probability_acc: u64,
    /// Whether we are in the repeat bits loop.
    pub is_repeat_bits_loop: bool,
    /// Whether this row represents the 0-7 trailing bits that should be ignored.
    pub is_trailing_bits: bool,
}

// Used for tracking bit markers for non-byte-aligned bitstream decoding
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BitstreamReadCursor {
    /// Start of the bit location within a byte [0, 8)
    pub bit_start_idx: usize,
    /// End of the bit location within a byte (0, 16)
    pub bit_end_idx: usize,
    /// The value of the bitstring
    pub bit_value: u64,
    /// Whether 0 bit is read
    pub is_zero_bit_read: bool,
    /// Indicator for when sequence data bitstream initial baselines are determined
    pub is_seq_init: bool,
    /// Idx of sequence instruction
    pub seq_idx: usize,
    /// The states (LLT, MLT, MOT) at this row
    pub states: [u64; 3],
    /// The symbols emitted at this state (LLT, MLT, MOT)
    pub symbols: [u64; 3],
    /// The values computed for literal length, match length and match offset.
    pub values: [u64; 3],
    /// The baseline value associated with this state.
    pub baseline: u64,
    /// Whether current byte is completely covered in a multi-byte packing scheme
    pub is_nil: bool,
    /// Indicate which exact state is the bitstring value is for
    /// 1. MOT Code to Value
    /// 2. MLT Code to Value
    /// 3. LLT Code to Value
    /// 4. LLT FSE update
    /// 5. MLT FSE update
    /// 6. MOT FSE update
    pub is_update_state: u64,
}

/// Sequence data is interleaved with 6 bitstreams. Each producing a different type of value.
#[derive(Clone, Copy, Debug)]
pub enum SequenceDataTag {
    LiteralLengthFse = 1,
    MatchLengthFse,
    CookedMatchOffsetFse,
    LiteralLengthValue,
    MatchLengthValue,
    CookedMatchOffsetValue,
}

/// A single row in the Address table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AddressTableRow {
    /// Whether this row is padding for positional alignment with input
    pub s_padding: u64,
    /// Instruction Index
    pub instruction_idx: u64,
    /// Literal Length (directly decoded from sequence bitstream)
    pub literal_length: u64,
    /// Cooked Match Offset (directly decoded from sequence bitstream)
    pub cooked_match_offset: u64,
    /// Match Length (directly decoded from sequence bitstream)
    pub match_length: u64,
    /// Accumulation of literal length
    pub literal_length_acc: u64,
    /// Repeated offset 1
    pub repeated_offset1: u64,
    /// Repeated offset 2
    pub repeated_offset2: u64,
    /// Repeated offset 3
    pub repeated_offset3: u64,
    /// The actual match offset derived from cooked match offset
    pub actual_offset: u64,
}

impl AddressTableRow {
    /// a debug helper, input data in the form of example in
    /// zstd spec: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#repeat-offsets
    /// i.e. [offset, literal, rep_1, rep_2, rep_3]
    #[cfg(test)]
    pub fn mock_samples(samples: &[[u64; 5]]) -> Vec<Self> {
        Self::mock_samples_full(
            samples
                .iter()
                .map(|sample| [sample[0], sample[1], 0, sample[2], sample[3], sample[4]]),
        )
    }

    /// build row with args [offset, literal, match_len, rep_1, rep_2, rep_3]    
    #[cfg(test)]
    pub fn mock_samples_full(samples: impl IntoIterator<Item = [u64; 6]>) -> Vec<Self> {
        let mut ret = Vec::<Self>::new();

        for sample in samples {
            let mut new_item = Self {
                cooked_match_offset: sample[0],
                literal_length: sample[1],
                match_length: sample[2],
                repeated_offset1: sample[3],
                repeated_offset2: sample[4],
                repeated_offset3: sample[5],
                actual_offset: sample[3],
                ..Default::default()
            };

            if let Some(old_item) = ret.last() {
                new_item.instruction_idx = old_item.instruction_idx + 1;
                new_item.literal_length_acc = old_item.literal_length_acc + sample[1];
            } else {
                new_item.literal_length_acc = sample[1];
            }

            ret.push(new_item);
        }

        ret
    }
}

/// Data for BL and Number of Bits for a state in LLT, CMOT and MLT
#[derive(Clone, Debug)]
pub struct SequenceFixedStateActionTable {
    /// Represent the state, BL and NB
    pub states_to_actions: Vec<(u64, (u64, u64))>,
}

impl SequenceFixedStateActionTable {
    /// Reconstruct action state table for literal length recovery
    pub fn reconstruct_lltv() -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=15 {
            states_to_actions.push((idx as u64, (idx as u64, 0u64)))
        }

        let rows: Vec<(u64, u64, u64)> = vec![
            (16, 16, 1),
            (17, 18, 1),
            (18, 20, 1),
            (19, 22, 1),
            (20, 24, 2),
            (21, 28, 2),
            (22, 32, 3),
            (23, 40, 3),
            (24, 48, 4),
            (25, 64, 6),
            (26, 128, 7),
            (27, 256, 8),
            (28, 512, 9),
            (29, 1024, 10),
            (30, 2048, 11),
            (31, 4096, 12),
            (32, 8192, 13),
            (33, 16384, 14),
            (34, 32768, 15),
            (35, 65536, 16),
        ];

        for row in rows {
            states_to_actions.push((row.0, (row.1, row.2)));
        }

        Self { states_to_actions }
    }

    /// Reconstruct action state table for match length recovery
    pub fn reconstruct_mltv() -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=31 {
            states_to_actions.push((idx as u64, (idx as u64 + 3, 0u64)))
        }

        let rows: Vec<(u64, u64, u64)> = vec![
            (32, 35, 1),
            (33, 37, 1),
            (34, 39, 1),
            (35, 41, 1),
            (36, 43, 2),
            (37, 47, 2),
            (38, 51, 3),
            (39, 59, 3),
            (40, 67, 4),
            (41, 83, 4),
            (42, 99, 5),
            (43, 131, 7),
            (44, 259, 8),
            (45, 515, 9),
            (46, 1027, 10),
            (47, 2051, 11),
            (48, 4099, 12),
            (49, 8195, 13),
            (50, 16387, 14),
            (51, 32771, 15),
            (52, 65539, 16),
        ];

        for row in rows {
            states_to_actions.push((row.0, (row.1, row.2)));
        }

        Self { states_to_actions }
    }

    /// Reconstruct action state table for offset recovery
    pub fn reconstruct_cmotv(n: u64) -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=n {
            states_to_actions.push((idx, ((1 << idx) as u64, idx)))
        }

        Self { states_to_actions }
    }
}

#[derive(Clone, Debug)]
/// Current state for decompression
pub struct ZstdDecodingState {
    /// Current decoding state during Zstd decompression
    pub state: ZstdState,
    /// Data cursor on compressed data
    pub encoded_data: EncodedDataCursor,
    /// Bitstream reader cursor
    pub bitstream_read_data: Option<BitstreamReadCursor>,
    /// decompressed data has been decoded
    pub decoded_data: Vec<u8>,
    /// Fse decoding state transition data
    pub fse_data: Option<FseDecodingState>,
    /// literal dicts
    pub literal_data: Vec<u64>,
    /// the repeated offset for sequence
    pub repeated_offset: [usize; 3],
}

impl ZstdDecodingState {
    /// Construct the init state of for decompression
    pub fn init(src_len: usize) -> Self {
        Self {
            state: ZstdState::default(),
            encoded_data: EncodedDataCursor {
                encoded_len: src_len as u64,
                ..Default::default()
            },
            decoded_data: Vec::new(),
            fse_data: None,
            bitstream_read_data: None,
            literal_data: Vec::new(),
            repeated_offset: [1, 4, 8], // starting values, according to the spec
        }
    }
}
