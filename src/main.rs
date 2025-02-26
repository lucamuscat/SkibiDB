use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    io::{Read, Seek, Write},
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    rc::Rc,
    str::Utf8Error,
};

#[derive(Hash, PartialEq, Eq)]
struct BlockId {
    file_name: String,
    block_number: usize,
}

#[derive(Debug)]
struct Page {
    byte_buffer: Box<[u8]>,
}

#[derive(Copy, Clone)]
struct Offset(usize);

#[derive(PartialEq, Eq, Debug, Clone)]
enum PageError {
    PageOverflow,
    Utf8Error(Utf8Error),
}

#[derive(Debug)]
enum FileManagerError {
    FileCreationError(std::io::Error),
    DatabaseDirCreationError(std::io::Error),
    WriteError(std::io::Error),
    ReadError(std::io::Error),
    MetadataError(std::io::Error),
}

impl Page {
    fn new(block_size: NonZeroUsize) -> Self {
        // Create a byte buffer with all bytes set to zero. Investigate MaybeUninint to avoid
        // initializing all values to zero.
        let byte_buffer = vec![0u8; block_size.get()].into_boxed_slice();
        Self { byte_buffer }
    }

    fn set_int(&mut self, offset: Offset, value: u64) -> Result<(), PageError> {
        // check the Write trait for Box<u8>
        if offset.0 + std::mem::size_of::<u64>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow);
        };

        self.byte_buffer[offset.0..offset.0 + std::mem::size_of::<u64>()]
            .copy_from_slice(&value.to_le_bytes());

        Ok(())
    }

    fn get_int(&self, offset: Offset) -> Result<usize, PageError> {
        if offset.0 + std::mem::size_of::<u64>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow);
        };

        let bytes = &self.byte_buffer[offset.0..offset.0 + std::mem::size_of::<u64>()];

        // TODO: Find a way to have this portable across both 32bit and 64 bit machines.
        Ok(usize::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn set_bytes(&mut self, offset: Offset, value: &[u8]) -> Result<(), PageError> {
        // We are also storing the size of the bytes alongsize the bytes themselves.
        // Make sure that there is also enough space for the length.
        if offset.0 + value.len() + std::mem::size_of::<u64>() > (self.byte_buffer.len() - 1) {
            return Err(PageError::PageOverflow);
        };

        self.set_int(offset, value.len() as u64).unwrap();

        let offset_after_size = offset.0 + std::mem::size_of::<u64>();

        self.byte_buffer[offset_after_size..offset_after_size + value.len()].copy_from_slice(value);

        Ok(())
    }

    fn get_bytes(&self, offset: Offset) -> Result<&[u8], PageError> {
        let length = self.get_int(offset)?;
        let offset_after_length = offset.0 + std::mem::size_of_val(&length);

        if offset_after_length + length > self.byte_buffer.len() - 1 {
            return Err(PageError::PageOverflow);
        };

        Ok(&self.byte_buffer[offset_after_length..offset_after_length + length])
    }

    fn set_string(&mut self, offset: Offset, value: impl AsRef<str>) -> Result<(), PageError> {
        self.set_bytes(offset, value.as_ref().as_bytes())
    }

    fn get_string(&self, offset: Offset) -> Result<&str, PageError> {
        std::str::from_utf8(self.get_bytes(offset)?).map_err(PageError::Utf8Error)
    }
}

struct FileManager {
    block_size: NonZeroUsize,
    database_dir: PathBuf,
    open_files: RefCell<HashMap<String, Rc<RefCell<File>>>>,
}

impl FileManager {
    fn new(database_dir: PathBuf, block_size: NonZeroUsize) -> Result<Self, FileManagerError> {
        match std::fs::create_dir(database_dir.as_path()) {
            Ok(_) => {}
            Err(err) => match err.kind() {
                std::io::ErrorKind::AlreadyExists => {}
                _ => return Err(FileManagerError::DatabaseDirCreationError(err)),
            },
        };

        // TODO: Add temp file removal logic

        Ok(Self {
            block_size,
            database_dir,
            open_files: RefCell::new(HashMap::new()),
        })
    }

    fn get_file(&self, file_name: &str) -> Result<Rc<RefCell<File>>, FileManagerError> {
        let mut open_files = self.open_files.borrow_mut();

        let file = open_files.get(file_name);

        if let Some(file) = file {
            return Ok(file.clone());
        };

        let file_path = self.database_dir.join(PathBuf::from(file_name));

        let file = Rc::new(RefCell::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(libc::O_SYNC)
                .open(file_path)
                .map_err(FileManagerError::FileCreationError)?,
        ));

        assert!(
            open_files.insert(file_name.into(), file.clone()).is_none(),
            "because the file is not supposed to be open"
        );

        Ok(file)
    }

    fn write(&self, block: &BlockId, page: &Page) -> Result<(), FileManagerError> {
        let file = self.get_file(&block.file_name)?;
        let mut file = file.borrow_mut();
        file.seek(std::io::SeekFrom::Start(
            (block.block_number * self.block_size.get()) as u64,
        ))
        .map_err(FileManagerError::WriteError)?;
        file.write(&page.byte_buffer)
            .map_err(FileManagerError::WriteError)?;
        Ok(())
    }

    fn read(&self, block: &BlockId, page: &mut Page) -> Result<(), FileManagerError> {
        let file = self.get_file(&block.file_name)?;
        let mut file = file.borrow_mut();
        file.seek(std::io::SeekFrom::Start(
            (block.block_number * self.block_size.get()) as u64,
        ))
        .map_err(FileManagerError::ReadError)?;
        file.read_exact(&mut page.byte_buffer)
            .map_err(FileManagerError::ReadError)?;
        Ok(())
    }

    /// Returns the number of blocks allocated to the file.
    fn length(&self, file_name: &str) -> Result<u64, FileManagerError> {
        let file = self.get_file(file_name)?;
        let metadata = file
            .borrow_mut()
            .metadata()
            .map_err(FileManagerError::MetadataError)?;

        Ok(metadata.size() / self.block_size.get() as u64)
    }
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, path::PathBuf};

    use rstest::rstest;
    use uuid::Uuid;

    use crate::{BlockId, FileManager, Offset, Page, PageError};

    fn uniquely_random_tmp_dir() -> PathBuf {
        std::env::temp_dir().join(Uuid::new_v4().to_string())
    }

    fn create_file_manager() -> FileManager {
        let db_path = uniquely_random_tmp_dir();
        FileManager::new(db_path.clone(), NonZeroUsize::new(BLOCK_SIZE).unwrap()).unwrap()
    }

    const BLOCK_SIZE: usize = 100;

    #[rstest]
    #[case::block_too_small(std::mem::size_of::<usize>() - 1, 0)]
    #[case::set_int_at_end_of_page(BLOCK_SIZE, BLOCK_SIZE - std::mem::size_of::<u64>() + 1)]
    #[case::set_int_overlapping_with_boundary_1(BLOCK_SIZE, BLOCK_SIZE - 1)]
    fn given_out_of_bounds_when_set_int_then_return_err(
        #[case] block_size: usize,
        #[case] offset: usize,
    ) {
        let mut system_under_test: Page = Page::new(NonZeroUsize::new(block_size).unwrap());

        assert!(
            matches!(system_under_test.set_int(Offset(offset), 5), Err(err1) if err1 == PageError::PageOverflow)
        );
    }

    #[rstest]
    #[case::safe_offset(BLOCK_SIZE, 20)]
    #[case::safe_offset(BLOCK_SIZE, BLOCK_SIZE - 1 - std::mem::size_of::<u64>())]
    fn when_set_int_then_roundtrip_works(#[case] block_size: usize, #[case] offset: usize) {
        let mut system_under_test: Page = Page::new(NonZeroUsize::new(block_size).unwrap());

        let expected_value = 1234u64;
        let expected_offset = Offset(offset);

        system_under_test
            .set_int(expected_offset, expected_value)
            .unwrap();
        assert_eq!(
            system_under_test.get_int(expected_offset).unwrap() as u64,
            expected_value
        )
    }

    #[test]
    fn when_set_bytes_then_roundtrip_works() {
        let mut system_under_test = Page::new(NonZeroUsize::new(BLOCK_SIZE).unwrap());

        let buffer: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];

        system_under_test
            .set_bytes(Offset(10), buffer.as_slice())
            .expect("Set bytes was expected to succeed");
        assert_eq!(
            system_under_test.get_bytes(Offset(10)).unwrap(),
            buffer.as_slice()
        )
    }

    #[test]
    fn given_length_of_bytes_are_too_long_when_get_bytes_then_return_err() {
        let mut system_under_test = Page::new(NonZeroUsize::new(BLOCK_SIZE).unwrap());

        let buffer: Vec<u8> = vec![0, 1, 2, 3, 4];

        system_under_test
            .set_bytes(Offset(0), buffer.as_slice())
            .expect("Set bytes was expected to succeed");
        system_under_test
            .set_int(Offset(0), 200)
            .expect("Set int was expected to succeed");

        assert!(
            matches!(system_under_test.get_bytes(Offset(0)), Err(err) if err == PageError::PageOverflow)
        )
    }

    #[test]
    fn given_db_dir_already_exists_when_new_then_ok_is_returned() {
        let db_path = uniquely_random_tmp_dir();
        FileManager::new(db_path.clone(), NonZeroUsize::new(BLOCK_SIZE).unwrap()).unwrap();
        FileManager::new(db_path, NonZeroUsize::new(100).unwrap()).unwrap();
    }

    #[test]
    fn when_new_then_db_path_dir_is_created() {
        let system_under_test = create_file_manager();

        let metadata = std::fs::metadata(system_under_test.database_dir)
            .expect("because the call to metadata was expected to succeed.");

        assert!(metadata.is_dir())
    }

    #[test]
    fn given_file_does_not_exist_when_get_file_then_file_is_created() {
        let system_under_test = create_file_manager();
        system_under_test.get_file("some_database").unwrap();

        assert!(std::fs::exists(system_under_test.database_dir.join("some_database")).unwrap())
    }

    #[test]
    fn when_file_mgr_write_read_roundtrip_then_same_page_is_returned() {
        let system_under_test = create_file_manager();

        let mut actual_page = Page::new(NonZeroUsize::new(BLOCK_SIZE).unwrap());

        let mut read_page = Page::new(NonZeroUsize::new(BLOCK_SIZE).unwrap());

        actual_page
            .set_bytes(Offset(20), &[1, 2, 3, 4, 5, 6, 7])
            .unwrap();

        let actual_block_id = BlockId {
            file_name: "testDB".into(),
            block_number: 0,
        };

        system_under_test
            .write(&actual_block_id, &actual_page)
            .unwrap();

        system_under_test
            .read(&actual_block_id, &mut read_page)
            .unwrap();

        assert_eq!(read_page.byte_buffer, actual_page.byte_buffer)
    }

    #[test]
    fn test_length() {
        let system_under_test = create_file_manager();

        let page = Page::new(NonZeroUsize::new(BLOCK_SIZE).unwrap());

        let file_name = "testDB".to_string();

        let expected_length = 2;

        let block_id_1 = BlockId {
            block_number: 0,
            file_name: file_name.clone(),
        };

        let block_id_2 = BlockId {
            block_number: 1,
            file_name: file_name.clone(),
        };

        system_under_test.write(&block_id_1, &page).unwrap();
        system_under_test.write(&block_id_2, &page).unwrap();

        assert!(
            matches!(system_under_test.length(file_name.as_str()), Ok(length) if length == expected_length)
        )
    }
}
