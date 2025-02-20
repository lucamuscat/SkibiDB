use std::{num::NonZeroUsize, str::Utf8Error};

#[derive(Hash, PartialEq, Eq)]
struct BlockId {
    file_name: String,
    block_number: u32
}

struct Page {
    byte_buffer: Box<[u8]>
}

#[derive(Copy, Clone)]
struct Offset(usize);

#[derive(PartialEq, Eq, Debug, Clone)]
enum PageError {
    PageOverflow,
    Utf8Error(Utf8Error)
}

impl Page {
    fn new(block_size: NonZeroUsize) -> Self {
        // Create a byte buffer with all bytes set to zero. Investigate MaybeUninint to avoid
        // initializing all values to zero.
        let byte_buffer = vec![0u8; block_size.get()].into_boxed_slice();
        Self {
            byte_buffer
        }
    }

    fn set_int(&mut self, offset: Offset, value: usize) -> Result<(), PageError>{
        // check the Write trait for Box<u8>
        if offset.0 + std::mem::size_of::<usize>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow)
        };

        self.byte_buffer[offset.0 .. offset.0 + std::mem::size_of::<usize>()].copy_from_slice(&value.to_le_bytes());

        Ok(())
    }

    fn get_int(&self, offset: Offset) -> Result<usize, PageError> {
        if offset.0 + std::mem::size_of::<u32>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow)
        };

        let bytes = &self.byte_buffer[offset.0 .. offset.0 + std::mem::size_of::<usize>()];

        // TODO: Find a way to have this portable across both 32bit and 64 bit machines.
        Ok(usize::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]))

    }


    fn set_bytes(&mut self, offset: Offset, value: &[u8]) -> Result<(), PageError>{
        // We are also storing the size of the bytes alongsize the bytes themselves.
        // Make sure that there is also enough space for the length.
        if offset.0 + value.len() + std::mem::size_of::<u32>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow)
        };

        self.set_int(offset, value.len()).unwrap();

        let offset_after_size = offset.0 + std::mem::size_of::<usize>();

        self.byte_buffer[offset_after_size .. offset_after_size + value.len()].copy_from_slice(value);

        Ok(())
    }

    fn get_bytes(&self, offset: Offset) -> Result<&[u8], PageError> {
        let length = self.get_int(offset)?;
        let offset_after_length = offset.0 + std::mem::size_of_val(&length);

        if offset_after_length + length > self.byte_buffer.len() - 1 {
            return Err(PageError::PageOverflow)
        };

        Ok(&self.byte_buffer[offset_after_length .. offset_after_length + length])
    }

    fn set_string(&mut self, offset: Offset, value: impl AsRef<str>) -> Result<(), PageError>{
        self.set_bytes(offset, value.as_ref().as_bytes())
    }


    fn get_string(&self, offset: Offset) -> Result<&str, PageError> {
        std::str::from_utf8(self.get_bytes(offset)?).map_err(PageError::Utf8Error)
    }


    // fn max_length ...
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use rstest::rstest;

    use crate::{Offset, Page, PageError};

    #[rstest]
    #[case::block_too_small(std::mem::size_of::<usize>() - 1, 0)]
    #[case::set_int_at_end_of_page(100, 100 - std::mem::size_of::<usize>() + 1)]
    fn given_out_of_bounds_when_set_int_then_return_err(#[case] block_size: usize, #[case] offset: usize) {
        let mut system_under_test: Page = Page::new(NonZeroUsize::new(block_size).unwrap());

        assert!(matches!(system_under_test.set_int(Offset(offset), 5), Err(err1) if err1 == PageError::PageOverflow));
    }

    #[test]
    fn when_set_int_then_roundtrip_works() {
        let mut system_under_test: Page = Page::new(NonZeroUsize::new(100).unwrap());

        let expected_value: usize = 1234usize;
        let expected_offset = Offset(20);

        system_under_test.set_int(expected_offset, expected_value).unwrap();
        assert_eq!(system_under_test.get_int(expected_offset).unwrap(), expected_value)
    }

    #[test]
    fn when_set_bytes_then_roundtrip_works() {
        let mut system_under_test = Page::new(NonZeroUsize::new(100).unwrap());

        let buffer: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];

        system_under_test.set_bytes(Offset(10), buffer.as_slice()).expect("Set bytes was expected to succeed");
        assert_eq!(system_under_test.get_bytes(Offset(10)).unwrap(), buffer.as_slice())
    }

    #[test]
    fn given_length_of_bytes_are_too_long_when_get_bytes_then_return_err() {
        let mut system_under_test = Page::new(NonZeroUsize::new(100).unwrap());

        let buffer: Vec<u8> = vec![0, 1, 2, 3, 4];

        system_under_test.set_bytes(Offset(0), buffer.as_slice()).expect("Set bytes was expected to succeed");
        system_under_test.set_int(Offset(0), 200).expect("Set int was expected to succeed");

        assert!(matches!(system_under_test.get_bytes(Offset(0)), Err(err) if err == PageError::PageOverflow))
    }
}