use bitstream_io::BE;
use bitstream_io::huffman::{compile_read_tree, compile_write_tree, ReadHuffmanTree, WriteHuffmanTree};

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd)]
pub enum DomainCode {
    Char(char),
    Composite(&'static str),
    End,
}
pub static COMPOSITE_CODES: [&str; 7] = ["www.", ".com", ".net", ".org", ".edu", ".gov", ".info"];
fn build_huffman_tree() -> Vec<(DomainCode, Vec<u8>)> {
    let mut raw_codes = Vec::<DomainCode>::new();
    raw_codes.push(DomainCode::End);
    for ch in u32::from('a')..=u32::from('z') {
        raw_codes.push(DomainCode::Char(char::from(ch as u8)));
    }
    for ch in ".-0123456789_".chars() {
        raw_codes.push(DomainCode::Char(ch));
    }
    for comp in COMPOSITE_CODES.iter() {
        raw_codes.push(DomainCode::Composite(comp));
    }
    assert_eq!(raw_codes.len(), 0b11111 + 0b1111 + 1);
    raw_codes.into_iter().enumerate().map(|(mut i, code)| {
        let is_extended = i >= 0b11111;
        let mut tree_bits = if is_extended {
            Vec::with_capacity(9)
        } else {
            Vec::with_capacity(5)
        };
        let num_bits = if !is_extended { 5 } else { 4 };
        if is_extended {
            i -= 0b11111;
        }
        for _ in 0..num_bits {
            tree_bits.push((i & 1) as u8);
            i = i >> 1;
        }
        if is_extended {
            tree_bits.extend(&[1, 1, 1, 1, 1]);
        }
        tree_bits.reverse();
        (code, tree_bits)
    }).collect()
}
lazy_static! {
    pub static ref READ_TREE: Box<[ReadHuffmanTree<BE, DomainCode>]> = compile_read_tree(build_huffman_tree()).unwrap();
    pub static ref WRITE_TREE: WriteHuffmanTree<BE, DomainCode> = compile_write_tree(build_huffman_tree()).unwrap();
}
