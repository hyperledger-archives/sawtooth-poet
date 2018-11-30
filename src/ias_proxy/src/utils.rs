/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

use std::fs::File;
use std::io::Read;

/// Utility function to accept file name (with path if present) and return contents of file as
/// String object. Note that error reading file would panic, because IAS proxy server cannot
/// function without reading file.
///
/// return: A String object
pub fn read_file_as_string(
    file_name: &str
) -> String {
    let mut file_reader = match File::open(file_name) {
        Ok(file_present) => file_present,
        Err(err) => panic!("File is not present: {}", err),
    };
    let mut file_contents = String::new();
    if file_reader.read_to_string(&mut file_contents).is_err() {
        panic!("Unable to read file")
    };
    return file_contents;
}

/// Reads binary file and returns vector of u8
///
/// Note: This method will panic if file is not found or error occurs when reading file as binary.
pub fn read_binary_file(
    filename: &str
) -> Vec<u8> {
    let mut file = File::open(filename).expect("File not found");
    let mut buffer = vec![];
    file.read_to_end(&mut buffer).expect("Read failed!");
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_file_as_string() {
        let file_contents = "This is dummy file and
These are random text words in the file
";
        let read_contents = read_file_as_string("src/tests/dummy_file.txt");
        assert_eq!(read_contents, file_contents);
    }

    #[test]
    #[should_panic]
    fn test_panic_when_non_existing_file_read() {
        read_file_as_string("non_existing_path/non_existing_file.non_existing_extension");
    }
}
